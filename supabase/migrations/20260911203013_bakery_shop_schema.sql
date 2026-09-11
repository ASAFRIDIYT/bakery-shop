-- Bakery shop: catalogue, orders, and an admin dashboard.
--
-- Everything lives in `public` with a bakery_ prefix. The shared Supabase project
-- already exposes `public` to the API; adding a dedicated schema would require
-- changing the project's exposed-schema list, and the only automated way to do that
-- (`supabase config push`) also rewrites unrelated auth settings from local template
-- defaults. Prefixes cost nothing and touch no project-wide configuration.

-- ---------------------------------------------------------------- admin identity

-- Who is an admin is decided by email, so an admin is an admin the moment they sign
-- up -- no chicken-and-egg where someone must exist before they can be promoted.
create table public.bakery_admins (
  email text primary key
);

alter table public.bakery_admins enable row level security;
-- No policies on purpose: this table is readable only through the definer function
-- below. Nobody queries it over the API, not even an admin.

insert into public.bakery_admins (email) values ('asimafridi929@gmail.com');

-- SECURITY DEFINER so the check can read bakery_admins while RLS blocks everyone
-- else. Without this, policies referencing the table would recurse or return false.
create or replace function public.bakery_is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.bakery_admins
    where email = (select auth.jwt() ->> 'email')
  );
$$;

revoke all on function public.bakery_is_admin() from public;
grant execute on function public.bakery_is_admin() to anon, authenticated;

-- -------------------------------------------------------------------- products

create table public.bakery_products (
  id               uuid primary key default gen_random_uuid(),
  name             text not null,
  description      text not null default '',
  price            numeric(10,2) not null check (price >= 0),
  discount_percent integer not null default 0
                     check (discount_percent between 0 and 90),
  image_url        text,
  is_available     boolean not null default true,
  created_at       timestamptz not null default now()
);

alter table public.bakery_products enable row level security;

-- The catalogue is public: a visitor must be able to browse before signing up.
-- Hidden items stay hidden from everyone except an admin.
create policy "catalogue is public"
  on public.bakery_products for select
  to anon, authenticated
  using (is_available or public.bakery_is_admin());

create policy "admins add products"
  on public.bakery_products for insert
  to authenticated
  with check (public.bakery_is_admin());

create policy "admins edit products"
  on public.bakery_products for update
  to authenticated
  using (public.bakery_is_admin())
  with check (public.bakery_is_admin());

create policy "admins remove products"
  on public.bakery_products for delete
  to authenticated
  using (public.bakery_is_admin());

-- ---------------------------------------------------------------------- orders

create table public.bakery_orders (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references auth.users(id) on delete cascade,
  customer_name text not null,
  phone         text not null,
  address       text not null,
  total         numeric(10,2) not null check (total >= 0),
  status        text not null default 'pending'
                  check (status in ('pending','confirmed','delivered','cancelled')),
  created_at    timestamptz not null default now()
);

alter table public.bakery_orders enable row level security;

-- The rule that matters: a customer sees their own orders and nobody else's.
create policy "own orders, or admin sees all"
  on public.bakery_orders for select
  to authenticated
  using (user_id = (select auth.uid()) or public.bakery_is_admin());

create policy "place own order"
  on public.bakery_orders for insert
  to authenticated
  with check (user_id = (select auth.uid()));

-- Only an admin moves an order along; a customer cannot mark their own order paid.
create policy "admins update orders"
  on public.bakery_orders for update
  to authenticated
  using (public.bakery_is_admin())
  with check (public.bakery_is_admin());

create policy "admins delete orders"
  on public.bakery_orders for delete
  to authenticated
  using (public.bakery_is_admin());

-- ----------------------------------------------------------------- order items

-- product_name and unit_price are copied in at purchase time so an order still
-- reads correctly after the product is renamed, repriced, or deleted.
create table public.bakery_order_items (
  id           uuid primary key default gen_random_uuid(),
  order_id     uuid not null references public.bakery_orders(id) on delete cascade,
  product_id   uuid references public.bakery_products(id) on delete set null,
  product_name text not null,
  qty          integer not null check (qty > 0),
  unit_price   numeric(10,2) not null check (unit_price >= 0)
);

alter table public.bakery_order_items enable row level security;

create policy "items follow their order"
  on public.bakery_order_items for select
  to authenticated
  using (exists (
    select 1 from public.bakery_orders o
    where o.id = order_id
      and (o.user_id = (select auth.uid()) or public.bakery_is_admin())
  ));

create policy "add items to own order"
  on public.bakery_order_items for insert
  to authenticated
  with check (exists (
    select 1 from public.bakery_orders o
    where o.id = order_id
      and o.user_id = (select auth.uid())
  ));

create index bakery_order_items_order_id_idx on public.bakery_order_items (order_id);
create index bakery_orders_user_id_idx on public.bakery_orders (user_id, created_at desc);

-- ---------------------------------------------------------------------- grants

-- RLS decides row visibility; these grants decide which verbs the API roles may
-- attempt at all. Both layers have to agree before anything happens.
grant select on public.bakery_products to anon, authenticated;
grant insert, update, delete on public.bakery_products to authenticated;

grant select, insert, update, delete on public.bakery_orders to authenticated;
grant select, insert on public.bakery_order_items to authenticated;

-- -------------------------------------------------------------- starter catalogue

insert into public.bakery_products (name, description, price, discount_percent, image_url) values
  ('Chocolate Fudge Cake', 'Rich cocoa sponge with dark chocolate ganache.', 2400.00, 10, 'https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=600&q=80'),
  ('Vanilla Cupcakes (6)',  'Soft vanilla cupcakes with buttercream swirl.',   900.00,  0, 'https://images.unsplash.com/photo-1486427944299-d1955d23e34d?w=600&q=80'),
  ('Butter Croissant',      'Flaky, layered, baked fresh every morning.',      180.00,  0, 'https://images.unsplash.com/photo-1555507036-ab1f4038808a?w=600&q=80'),
  ('Red Velvet Slice',      'Cream cheese frosting, single generous slice.',   450.00, 15, 'https://images.unsplash.com/photo-1586788680434-30d324b2d46f?w=600&q=80'),
  ('Almond Biscotti (250g)','Twice-baked, best with chai.',                    650.00,  0, 'https://images.unsplash.com/photo-1509440159596-0249088772ff?w=600&q=80'),
  ('Fresh Bread Loaf',      'Daily sourdough, crusty outside and soft inside.',320.00,  0, 'https://images.unsplash.com/photo-1549931319-a545dcf3bc73?w=600&q=80');
