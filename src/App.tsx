import { PublicChargePage } from './pages/PublicChargePage';
import './styles.css';

export default function App() {
  if (window.location.pathname.startsWith('/c/')) {
    return <PublicChargePage />;
  }

  return (
    <main className="card">
      <p className="eyebrow">Karo</p>
      <h1>Aplicação Vite configurada</h1>
      <p>Use uma URL pública no formato /c/:public_id para consultar uma cobrança.</p>
    </main>
  );
}
