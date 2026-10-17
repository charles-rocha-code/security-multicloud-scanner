## MODIFIED Requirements

### Requirement: Falha de tool não derruba a resposta
Quando a execução de uma tool falhar (erro do auditor, credencial ausente, SSRF recusado, kubeconfig recusado ou tempo limite excedido), o sistema SHALL devolver o erro como `tool_result` de erro para o modelo continuar o raciocínio, em vez de propagar uma exceção não tratada que derruba a requisição inteira. Quando a tool exceder o tempo limite configurado, o sistema SHALL parar de esperar por ela dentro desse limite (com folga de no máximo alguns segundos), e SHALL limitar quantas execuções de tool podem continuar rodando em segundo plano ao mesmo tempo, recusando novas execuções com erro de tool quando esse limite estiver atingido — para que tools lentas não esgotem a capacidade do servidor de atender outras requisições.

#### Scenario: Auditor de K8s falha por kubeconfig ausente
- **WHEN** o modelo invoca a tool de auditoria K8s e o auditor lança uma exceção (ex.: kubeconfig ausente/inválido)
- **THEN** o usuário recebe uma resposta final coerente (ex.: "não foi possível rodar a auditoria K8s: <motivo>"), não um erro 500 genérico

#### Scenario: Auditoria K8s mais lenta que o tempo limite
- **WHEN** o modelo invoca a tool de auditoria K8s e o cluster demora mais que o tempo limite da tool para responder
- **THEN** a tool devolve um erro de tempo limite em até o tempo limite configurado (mais poucos segundos de folga), e o usuário recebe uma resposta final coerente sem esperar a auditoria terminar

#### Scenario: Muitas auditorias presas ao mesmo tempo
- **WHEN** o número de auditorias K8s ainda rodando em segundo plano (após terem excedido o tempo limite) atinge o máximo permitido e o modelo invoca a tool de novo
- **THEN** a nova invocação devolve imediatamente um erro de tool indicando que o scanner está ocupado, sem iniciar outra auditoria
