# Arquitetura e limites

O parser separa ingestão, normalização temporal e correlação. Os eventos são ordenados por instante; a janela inclui o limite exato. Uma rajada gera um alerta até o número de falhas cair abaixo do limiar; um sucesso correlacionado limpa a janela. Retorno CLI: 0 sem alertas, 1 com alertas, 2 erro.

Aceita somente timestamps ISO com fuso e mensagens OpenSSH Failed/Accepted password/publickey. Syslog tradicional sem ano precisa ser normalizado antes. Linhas incompatíveis são contadas: confira ignored_lines antes de confiar no resultado. Logs são carregados em memória; não há streaming ou armazenamento persistente. IP compartilhado por NAT pode gerar falso positivo; ataques distribuídos podem não atingir o limiar. Login após falhas é sinal de triagem, não prova de comprometimento. Proteja os relatórios, pois contêm usuários e endereços.

Próxima evolução: parser de journald JSON e correlação distribuída com testes de volume.
