-- Fix: placing an order failed with "An order total cannot be edited after the fact".
--
-- The previous version inserted the order with total 0, added the items, then updated
-- the total -- and the guard trigger added in the same migration correctly refused
-- that update. The guard is right; the order of operations was wrong.
--
-- Resolve every line first, then insert the order with its final total already set,
-- then insert the items. No update, nothing for the guard to object to, and the
-- order row is never briefly visible carrying a total of zero.

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
  v_user     uuid := auth.uid();
  v_order    uuid;
  v_total    numeric(10,2) := 0;
  v_item     jsonb;
  v_p        public.bakery_products%rowtype;
  v_qty      integer;
  v_unit     numeric(10,2);
  v_recent   integer;
  v_name     text := trim(p_customer_name);
  v_phone    text := trim(p_phone);
  v_addr     text := trim(p_address);
  v_seen     uuid[] := '{}';
  v_pid      uuid;
  v_resolved jsonb := '[]'::jsonb;
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

  -- Pass one: price every line from the products table and add it up.
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

    v_resolved := v_resolved || jsonb_build_object(
      'product_id',   v_p.id,
      'product_name', v_p.name,
      'qty',          v_qty,
      'unit_price',   v_unit
    );
  end loop;

  -- Pass two: write it, already complete.
  insert into public.bakery_orders (user_id, customer_name, phone, address, total)
  values (v_user, v_name, v_phone, v_addr, v_total)
  returning id into v_order;

  insert into public.bakery_order_items
    (order_id, product_id, product_name, qty, unit_price)
  select v_order,
         (e ->> 'product_id')::uuid,
         e ->> 'product_name',
         (e ->> 'qty')::integer,
         (e ->> 'unit_price')::numeric
    from jsonb_array_elements(v_resolved) e;

  perform public.bakery_notify_order(v_order);

  return v_order;
end;
$$;

revoke all on function public.bakery_place_order(text, text, text, jsonb)
  from public, anon;
grant execute on function public.bakery_place_order(text, text, text, jsonb)
  to authenticated;
