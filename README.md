# ssh-watch

**Área do portfólio:** [Cybersecurity](https://github.com/alefkaue#cybersecurity) · **Contexto:** Projeto pessoal

[![Tests](https://github.com/alefkaue/ssh-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/ssh-watch/actions/workflows/tests.yml)

Detecção de força bruta SSH em logs. Projeto independente de portfólio voltado a **SOC / detecção e triagem**.

Processa linhas de OpenSSH com timestamp ISO 8601 e fuso horário (formato RFC3339).
    Agrupa falhas por IP em janelas deslizantes e sinaliza login aceito após uma rajada.
    O relatório contém evidências, usuários envolvidos e horário da detecção.

## Executar

Requer Python 3.11 ou superior. Usa somente a biblioteca padrão; não precisa instalar pacotes.

```console
git clone https://github.com/alefkaue/ssh-watch.git
cd ssh-watch
python ssh_watch.py examples/auth.log --threshold 3
```

As ferramentas escrevem JSON em stdout. Use `--help` para consultar opções. Exemplos são sintéticos e não contêm dados reais.

O exemplo produz dois achados para `192.0.2.10`: `ssh_failure_burst` na terceira falha e `ssh_success_after_failures` no login seguinte. O código de saída é **1**, indicando achados, não falha da execução. Com `--threshold 4`, o mesmo exemplo não gera alerta.

## Testes

```console
python -m unittest discover -s tests -v
```

A automação executa a suíte em Windows e Linux, com Python 3.11 e 3.13.

## Decisões e limites

Veja [a arquitetura](docs/architecture.md) para o modelo de ameaça, decisões e limitações. Este é um laboratório educacional: os resultados exigem contexto e validação humana. Não substitui um SIEM, EDR ou avaliação completa de segurança.

## Exercício para demonstração

Execute o exemplo, explique cada campo do JSON e altere a entrada para observar a mudança no resultado. Os testes documentam casos de detecção e de comportamento esperado.

## Desenvolvimento

Código inicial desenvolvido com assistência de IA. O repositório explicita o escopo e usa dados sintéticos para permitir revisão e reprodução. Sugestões e correções podem ser propostas por issues e pull requests. Licença MIT.
