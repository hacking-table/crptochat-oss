# Política de segurança

## Como reportar uma vulnerabilidade

Não abra issue pública para falhas de segurança.

Use o **Private Vulnerability Reporting** do GitHub: na aba **Security** deste
repositório, clique em **Report a vulnerability**. O relato fica visível só para
o mantenedor até a correção sair.

Inclua, se puder: versão (`crptochat --version`), passos para reproduzir,
impacto esperado e uma prova de conceito.

## O que esperar

- Confirmação de recebimento em alguns dias.
- Correção publicada numa release assinada; o crédito vai para quem reportou,
  se quiser.

## Escopo

Cliente, servidor, protocolo e criptografia (`crptochat/`), o instalador e o
mecanismo de atualização assinada (`crptochat/update.py`, `packaging/`), e os
workflows de CI/release.

As releases oficiais são assinadas com a chave do mantenedor. Forks devem
gerar a própria chave (`python -m crptochat.update genkey`); um fork não
consegue publicar atualização para quem usa os binários oficiais.
