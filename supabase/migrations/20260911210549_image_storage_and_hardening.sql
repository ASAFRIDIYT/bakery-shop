-- Product image uploads, plus a round of hardening on the order path.

-- --------------------------------------------------------------- image bucket

-- Public read: a product photo has to load for a visitor who is not signed in.
-- Writing is another matter entirely -- see the policies below.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'bakery-products',
  'bakery-products',
  true,
  3145728,                                              -- 3 MB
  array['image/jpeg','image/png','image/webp','image/gif','image/avif']
)
on conflict (id) do update
  set public             = excluded.public,
      file_size_limit    = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- The bucket being "public" only makes objects readable. Every write still has to
-- pass these, and they ask the same admin check the rest of the app uses.
drop policy if exists "bakery images are readable" on storage.objects;
create policy "bakery images are readable"
  on storage.objects for select
  to anon, authenticated
  using (bucket_id = 'bakery-products');

drop policy if exists "admins upload bakery images" on storage.objects;
create policy "admins upload bakery images"
  on storage.objects for insert
  to authenticated
  with check (bucket_id = 'bakery-products' and public.bakery_is_admin());

drop policy if exists "admins replace bakery images" on storage.objects;
create policy "admins replace bakery images"
  on storage.objects for update
  to authenticated
  using (bucket_id = 'bakery-products' and public.bakery_is_admin())
  with check (bucket_id = 'bakery-products' and public.bakery_is_admin());

drop policy if exists "admins delete bakery images" on storage.objects;
create policy "admins delete bakery images"
  on storage.objects for delete
  to authenticated
  using (bucket_id = 'bakery-products' and public.bakery_is_admin());

-- ------------------------------------------------------- product field limits

-- Unbounded text columns are an open invitation to store a megabyte of junk in a
-- product name. Nothing legitimate comes near these ceilings.
alter table public.bakery_products
  add constraint bakery_products_name_len
    check (char_length(name) between 1 and 120),
  add constraint bakery_products_desc_len
    check (char_length(description) <= 500),
  add constraint bakery_products_image_url_len
    check (image_url is null or char_length(image_url) <= 500),
  add constraint bakery_products_price_ceiling
    check (price <= 1000000);

-- An image_url must be a URL we are willing to render, not javascript: or data:.
alter table public.bakery_products
  add constraint bakery_products_image_url_scheme
    check (image_url is null or image_url ~ '^https://');

-- ----------------------------------------------------- harden order placement

create or replace function public.bakery_place_order(
  p_customer_name text,
  p_phone         text,
  p_address       text,
  p_items         jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user   uuid := auth.uid();
  v_order  uuid;
  v_total  numeric(10,2) := 0;
  v_item   jsonb;
  v_p      public.bakery_products%rowtype;
  v_qty    integer;
  v_unit   numeric(10,2);
  v_recent integer;
  v_name   text := trim(p_customer_name);
  v_phone  text := trim(p_phone);
  v_addr   text := trim(p_address);
  v_seen   uuid[] := '{}';
  v_pid    uuid;
begin
  -- Runs as its owner, so RLS is not consulted. Every check lives here.
  if v_user is null then
    raise exception 'You must be signed in to place an order';
  end if;

  if v_name = '' or v_phone = '' or v_addr = '' then
    raise exception 'Name, phone and address are all required';
  end if;

  if char_length(v_name) > 80 then
    raise exception 'Name is too long';
  end if;
  if char_length(v_addr) > 400 then
    raise exception 'Address is too long';
  end if;

  -- Permissive on shape (people write numbers many ways), strict on length and
  -- on what characters may be stored at all.
  if v_phone !~ '^[0-9+()\- ]{7,20}$' then
    raise exception 'Enter a valid phone number';
  end if;

  if p_items is null or jsonb_typeof(p_items) <> 'array'
     or jsonb_array_length(p_items) = 0 then
    raise exception 'Your cart is empty';
  end if;

  if jsonb_array_length(p_items) > 50 then
    raise exception 'Too many different items in one order';
  end if;

  -- A signed-in account is not a licence to flood the shop with orders.
  select count(*) into v_recent
    from public.bakery_orders
   where user_id = v_user
     and created_at > now() - interval '1 hour';

  if v_recent >= 10 then
    raise exception 'Too many orders in the last hour. Please try again later.';
  end if;

  insert into public.bakery_orders (user_id, customer_name, phone, address, total)
  values (v_user, v_name, v_phone, v_addr, 0)
  returning id into v_order;

  for v_item in select * from jsonb_array_elements(p_items)
  loop
    begin
      v_pid := (v_item ->> 'product_id')::uuid;
      v_qty := (v_item ->> 'qty')::integer;
    exception when others then
      raise exception 'Malformed cart item';
    end;

    if v_pid = any (v_seen) then
      raise exception 'The same item appears twice in the cart';
    end if;
    v_seen := v_seen || v_pid;

    if v_qty is null or v_qty < 1 or v_qty > 99 then
      raise exception 'Quantity must be between 1 and 99';
    end if;

    select * into v_p
      from public.bakery_products
     where id = v_pid
       and is_available;

    if not found then
      raise exception 'One of the items is no longer available';
    end if;

    -- The price the customer pays, decided here and nowhere else.
    v_unit  := round(v_p.price * (100 - v_p.discount_percent) / 100.0, 2);
    v_total := v_total + v_unit * v_qty;

    insert into public.bakery_order_items
      (order_id, product_id, product_name, qty, unit_price)
    values (v_order, v_p.id, v_p.name, v_qty, v_unit);
  end loop;

  update public.bakery_orders set total = v_total where id = v_order;

  perform public.bakery_notify_order(v_order);

  return v_order;
end;
$$;

revoke all on function public.bakery_place_order(text, text, text, jsonb)
  from public, anon;
grant execute on function public.bakery_place_order(text, text, text, jsonb)
  to authenticated;

-- ------------------------------------------------- lock down status transitions

-- Admins may move an order along, but not into a value the app does not know, and
-- not by rewriting who placed it or what it cost.
create or replace function public.bakery_orders_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.user_id is distinct from old.user_id then
    raise exception 'An order cannot change hands';
  end if;
  if new.total is distinct from old.total then
    raise exception 'An order total cannot be edited after the fact';
  end if;
  return new;
end;
$$;

drop trigger if exists bakery_orders_guard_trg on public.bakery_orders;
create trigger bakery_orders_guard_trg
  before update on public.bakery_orders
  for each row execute function public.bakery_orders_guard();
