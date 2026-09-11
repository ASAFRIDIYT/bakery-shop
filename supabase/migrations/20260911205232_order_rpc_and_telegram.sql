-- Move order placement into the database, and notify Telegram when one arrives.
--
-- Until now the browser sent the prices and the total it had calculated. RLS controls
-- WHO may write a row, not WHAT is in it, so a tampered request could have bought a
-- Rs 2,400 cake for Rs 1. From here the client sends only product ids and quantities;
-- every price is read from bakery_products inside this transaction.

-- ------------------------------------------------------------------- settings

-- Not secret (a chat id identifies a conversation, it does not grant access to it),
-- but kept out of reach anyway so the recipient list can only change deliberately.
create table public.bakery_settings (
  key   text primary key,
  value text not null
);

alter table public.bakery_settings enable row level security;
-- No policies: read only from the security definer functions below.

insert into public.bakery_settings (key, value)
values ('telegram_chat_id', '6106398361');

-- --------------------------------------------------------------- notification

-- The bot token lives in Vault, never in this repository. pg_net posts from
-- Supabase's own servers, so it is unaffected by whether Telegram is reachable
-- from the shop owner's network.
create or replace function public.bakery_notify_order(p_order_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token text;
  v_chat  text;
  v_order public.bakery_orders%rowtype;
  v_items text;
  v_text  text;
begin
  select decrypted_secret into v_token
    from vault.decrypted_secrets
   where name = 'telegram_bot_token';

  select value into v_chat
    from public.bakery_settings
   where key = 'telegram_chat_id';

  -- A missing token must never take the order down with it.
  if v_token is null or v_chat is null then
    return;
  end if;

  select * into v_order from public.bakery_orders where id = p_order_id;
  if not found then
    return;
  end if;

  select string_agg(
           '• ' || product_name || ' x' || qty ||
           ' — Rs ' || trim(to_char(round(unit_price * qty), 'FM999999999')),
           E'\n' order by product_name)
    into v_items
    from public.bakery_order_items
   where order_id = p_order_id;

  v_text :=
    '🧾 New order — Rs ' || trim(to_char(round(v_order.total), 'FM999999999')) || E'\n\n' ||
    v_order.customer_name || ' · ' || v_order.phone || E'\n' ||
    v_order.address || E'\n\n' ||
    coalesce(v_items, '(no items)') || E'\n\n' ||
    'Status: ' || v_order.status;

  perform net.http_post(
    url     := 'https://api.telegram.org/bot' || v_token || '/sendMessage',
    body    := jsonb_build_object('chat_id', v_chat, 'text', v_text),
    headers := '{"Content-Type": "application/json"}'::jsonb
  );
end;
$$;

revoke all on function public.bakery_notify_order(uuid) from public, anon, authenticated;

-- -------------------------------------------------------------- place an order

-- p_items: [{"product_id": "...", "qty": 2}, ...]
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
  v_user  uuid := auth.uid();
  v_order uuid;
  v_total numeric(10,2) := 0;
  v_item  jsonb;
  v_p     public.bakery_products%rowtype;
  v_qty   integer;
  v_unit  numeric(10,2);
begin
  -- This function runs as its owner and so bypasses RLS entirely. Every check the
  -- policies would have made has to be made here instead, starting with identity.
  if v_user is null then
    raise exception 'You must be signed in to place an order';
  end if;

  if coalesce(trim(p_customer_name), '') = ''
     or coalesce(trim(p_phone), '') = ''
     or coalesce(trim(p_address), '') = '' then
    raise exception 'Name, phone and address are all required';
  end if;

  if p_items is null or jsonb_array_length(p_items) = 0 then
    raise exception 'Your cart is empty';
  end if;

  if jsonb_array_length(p_items) > 50 then
    raise exception 'Too many different items in one order';
  end if;

  insert into public.bakery_orders (user_id, customer_name, phone, address, total)
  values (v_user, trim(p_customer_name), trim(p_phone), trim(p_address), 0)
  returning id into v_order;

  for v_item in select * from jsonb_array_elements(p_items)
  loop
    v_qty := (v_item ->> 'qty')::integer;

    if v_qty is null or v_qty < 1 or v_qty > 99 then
      raise exception 'Quantity must be between 1 and 99';
    end if;

    select * into v_p
      from public.bakery_products
     where id = (v_item ->> 'product_id')::uuid
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

-- ------------------------------------------------- close the direct write path

-- With placement owned by the function above, a direct insert is only a way to write
-- a price nobody checked. Remove the grant so the function is the one way in.
revoke insert on public.bakery_orders from authenticated;
revoke insert on public.bakery_order_items from authenticated;

drop policy if exists "place own order" on public.bakery_orders;
drop policy if exists "add items to own order" on public.bakery_order_items;
