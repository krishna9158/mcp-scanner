CREATE TABLE public.payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    amount numeric NOT NULL,
    created_at timestamptz DEFAULT now()
);
