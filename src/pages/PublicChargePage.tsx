import { useEffect, useMemo, useState } from 'react';
import { supabase } from '../integrations/supabase/client';

type Charge = {
  id: string;
  public_id: string;
  amount?: number | null;
  description?: string | null;
  status?: string | null;
  due_date?: string | null;
  payer_name?: string | null;
  payment_url?: string | null;
};

type LoadState =
  | { status: 'loading' }
  | { status: 'not-found' }
  | { status: 'error'; message: string }
  | { status: 'loaded'; charge: Charge };

function usePublicIdFromPath() {
  return useMemo(() => {
    const match = window.location.pathname.match(/^\/c\/([^/?#]+)/);
    return match?.[1] ? decodeURIComponent(match[1]) : '';
  }, []);
}

export function PublicChargePage() {
  const publicId = usePublicIdFromPath();
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;

    async function loadCharge() {
      if (!publicId) {
        setState({ status: 'not-found' });
        return;
      }

      const { data, error } = await supabase
        .from('charges')
        .select('*')
        .eq('public_id', publicId)
        .maybeSingle();

      if (cancelled) {
        return;
      }

      if (error) {
        setState({ status: 'error', message: error.message });
        return;
      }

      if (!data) {
        setState({ status: 'not-found' });
        return;
      }

      setState({ status: 'loaded', charge: data as Charge });
    }

    loadCharge();

    return () => {
      cancelled = true;
    };
  }, [publicId]);

  if (state.status === 'loading') {
    return <main className="card">Carregando cobrança...</main>;
  }

  if (state.status === 'not-found') {
    return <main className="card">Cobrança não encontrada.</main>;
  }

  if (state.status === 'error') {
    return <main className="card error">Erro ao carregar cobrança: {state.message}</main>;
  }

  const { charge } = state;
  const formattedAmount =
    typeof charge.amount === 'number'
      ? new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(charge.amount)
      : null;

  return (
    <main className="card">
      <p className="eyebrow">Cobrança</p>
      <h1>{charge.description || 'Cobrança disponível'}</h1>
      {charge.payer_name ? <p>Pagador: {charge.payer_name}</p> : null}
      {formattedAmount ? <p className="amount">{formattedAmount}</p> : null}
      {charge.due_date ? <p>Vencimento: {new Date(charge.due_date).toLocaleDateString('pt-BR')}</p> : null}
      {charge.status ? <p>Status: {charge.status}</p> : null}
      {charge.payment_url ? (
        <a className="button" href={charge.payment_url} rel="noreferrer">
          Pagar cobrança
        </a>
      ) : null}
    </main>
  );
}
