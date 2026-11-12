# Como contribuir

PRs são bem-vindos!

1. Faça um fork e crie um branch a partir da `main`.
2. Rode os testes antes de abrir o PR:

   ```bash
   python3 -m venv .venv && . .venv/bin/activate
   pip install -e '.[dev]'
   pytest -q
   ```

3. Abra o PR explicando o que muda e por quê. Mudanças de protocolo ou de
   criptografia precisam de testes e de uma descrição do modelo de ameaça.

Para entrar na `main`, o CI (testes e checagens de segurança) precisa passar e o
PR precisa da aprovação do mantenedor. Não inclua segredos, chaves, IPs ou
dados pessoais em commits, issues ou PRs.

Falhas de segurança: veja [SECURITY.md](SECURITY.md), não abra issue pública.
