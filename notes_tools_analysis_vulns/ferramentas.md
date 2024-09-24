# Anotações gerais sobre ferramentas do kali linux

## Sqlmap

* Explora falhas de banco de dados - ex: sql injection

* ```sqlmap -u <url>```
  
* ```sqlmap -r <arquivo raw>```

* comando ```--dbs``` -> vejo nome bancos

* posso ver informações específicas do banco: ```-D <banco> --tables```

* depois ```-D <banco> -T <tabela> --columns```

## Wifite

* vejo redes wifi disponiveis e consigo conectar se tiver dispositivos usando

## Masscan

* Ferramenta para análises em massa na internet

* Não retorna informações sobre vulnerabilidades

## Netdiscover

* ```netdiscover -i <interface> -r <ip / mascara>```

* vejo info de dispositivos na rede

## Nmap

* Usar parâmetro ```-v``` para aumentar verbosidade

* ```nmap -sP <ip/mascara>```
 retorna todos os ips da rede (só faço ping)

* ```nmap -sL <ip/mascara>```
    retorna lista dispositivos sem scan de portas
  
* ```nmap -sT <ip>``` (T = TCP, fullscan)
  retorna portas abertas e o que esta rodando
  (pode ser considerado como ataque, quem adm a rede consegue perceber scan)
  
* ```nmap -sS -p <portas separadas , > <ip>``` (S = stealthy)
 igual comando acima, mas não é considerado ataque
  
* ```nmap -p <porta> <ip>```
 faço consulta se determinada porta está aberta, não é considerado ataque
  
* ```sudo nmap -sT -p <portas separadas , > <ip/mascara>```
 vejo detalhes das portas
  
* ```sudo nmap -O <ip>```
 vejo sistema operacional máquina (retorna % de chances de acerto para diferentes sistemas)
  
* ```nmap -sV <ip>```
 vejo mais detalhes de escaneamentos, portas abertas, versões de serviços. Analise extensiva e agressiva
  
* ```nmap -A <ip>``` (A=agressive)
 sistema operacional, versão protocolos, portas abertas, traceroute... -> todas funcoinalidades.
  
* ```nmap ... -D <ip_decoy>``` (D = decoy **pesquisar mais**)
  
* Nmap possui scripts para automatizar varreduras

  * Pasta ```/usr/share/nmap/scripts```

  * [Guia scripts](https://www.ninjaos.org/user_guides/nmap_scripts.pdf)

  * [Informação scripts vulnerabilidades](https://www.stationx.net/nmap-vulnerability-scan/#:~:text=It%20uses%20the%20National%20Vulnerability,local%20network%2C%20even%20when%20offline.)

  * vulns especificas

  * portas abertas

    * Possível ver [detalhes sobre as portas](https://nmap.org/book/man-port-scanning-basics.html) (aberta, fechada, resposta filtrada ...) além de detalhes da resposta ICMP (reset TTL, port-unreach ...)

  * listar cves

  * Mostra exploits

  * ssl injection

  * firewall (firewalk e waf)

    * Importante: Rodar com parâmetro ```-script-args=firewalk.max-probed-ports=-1``` (analisar todas as portas) e ```--traceroute``` (precisa habilitar pro script funcionar, já que analisa os filtros feitos por diferentes hosts)

  * Scripts: Independentes. Adicionados por usuários do github

    * Utilizam diferentes bases de dados: Vulners (api), OpenVAS, ExploitDB ...

    * Escritos com padrão Nmap Scripting Engine (NSE) - Baseado em Lua

    * Controle fino dos pacotes binários enviados nas requisições para testar vulnerabilidades e descobrir informações na rede

  * Utilizo com ```nmap --script <nome script> <<<parametros>>>``` ( se aperto enter mostra progresso do script)

  * Possível aumentar quantidade de scripts do nmap baixando outros já prontos

  * Atualizo com ```nmap --scrip-updated```

  * Scripts funcionam em baixo nível no geral, mandando requisições, construindo pacotes, match de regex ...

  * [Scripts possuem categorias](https://nmap.org/book/nse-usage.html#nse-categories)

    * Categoria < vuln > : 36 scripts para verificar CVEs

    * Ex: [Slowloris](https://github.com/nmap/nmap/blob/667527c4b46abb9cceef7a8b30a1f8a7e5d04d49/scripts/http-slowloris-check.nse), NMAp faz verificação manual e checa resultados das requisições para testar a existência das vulnerabilidades, já OpenVAS por exemplo apenas faz o teste de versão da aplicação para retornar se existe a vulnerabilidade, não testando efetivamente. [Discussão no Google Docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.oagedctd0)

* Parametro: ```-oX <nome_arquivo_xml_saida>``` é gerado um arquivo XML com os resultados

  * Útil para uso no zenmap (discutido abaixo)

  * Possível transformar o .xml em HTML: ```$ xsltproc <arquivo_xml_entrada> -o <arquivo_hmtl_saida>```

## Zenmap

* [Repositório](https://nmap.org/book/zenmap.html)

* interface gráfica para o nmap

* Útil -> Gerar topologia da rede, facilita identificação visual dos dispositivos e sumariza informações.

  * Utilizar com resultados .xml do NMap com o scan realizado utilizando a flag ```--traceroute```

## Wireshark

* monitoro trafego

* vejo pacotes enviados e informações

* se não tem https, fácil de ver conteudo trocado entre cliente / server

* tem diferentes 'profiles' -> configurações

* mostra timestamp de conexão / requisão de dispositivos

* consigo exportar escaneamento para csv

## Metasploit

* Versão de código aberto ou comercial

* ```msfconsole``` abre terminal do metasploit

* Trabalha com módulos que realizam os exploits. 

  * Pesquiso com ```search```

    * ex: ```search type:<ex: exploit> platform:<ex: windows>``` para usar exploit -> preciso associar a payload (carrega exploit)

  * após encontrar, ```set <payload name>``` para usar. Ao digitar ```info``` são retornados os parâmetros necessários para a execução.

  * Alguns exploits possuem comando ```check``` para [checar se a vulnerabilidade existe antes de realizar o exploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-check()-method/7ab477018e5ed45f7b8b1b32b9ab7e7a17ba3126).

  * Comando ```run``` executa

  * Importante: Tomar cuidado com alguns módulos, podem ser muito agressivos.

    * Importante analisar a qualidade do teste realizado pelo Metasploit, semelhante ao QOD do OpenVAS que mede a qualidade da detecção, porém no caso o ['ranking'](https://docs.metasploit.com/docs/using-metasploit/intermediate/exploit-ranking.html) utilizado pelo metasploit determina a chance do exploit ter sucesso.

* [Possíveis retornos para vulnerabilidades](https://docs.metasploit.com/api/Msf/Exploit/CheckCode.html)

* [Script para buscar lista de CVEs no metasploit](https://github.com/tunnelcat/metasploit-cve-search )

## Sn1per

* Attack surface manangment

* Usa NMap para enumerar portas, reconhecimento, scripts em portas abertas.

* Usa modulos de exploração do Metasploit

* Utiliza outras ferramentas para analise e exploracao (Smuggler - requisicoes HTTP, gospider - crawler, WAF - firewall ...)

* [Ferramentas integradas pelo Sn1per](https://github.com/1N3/Sn1per/wiki/Plugins-&-Tools)

* [Descrição inicial da ferramenta](https://mindsetsecurity.wordpress.com/2018/04/24/sn1per/)

* [Repositorio Sn1per](https://github.com/1N3/Sn1per?tab=readme-ov-file)

* Ferramenta completa (agrega diversas outras ferramentas individuais), relizando várias análises de uma só vez.

  * Busca serviços, portas, versões, sistemas operacionais, checa vulnerabilidades, cabeçalhos web, ips de uma rede ...

  * Consigo ver informações de ssh

  * Realiza bruteforces através do metasploit

  * Informações de reconhecimento (emails / usuarios no sistema de arquivos / informações do whois ...)

  * Gera dump com saída das ferramentas utilizadas

* Gera várias pastas com os resultados obtidos.

  * Sumariza informações na pasta ```/usr/share/sniper/loot/workspace```

* ```sniper -t <ip ou rede>``` -> analise normal

* ```sniper -t <ip ou rede> -m discover``` -> exploração de rede

* Tem sobreposiço de informaçoes (subferramentas acabam gerando resultados já vistos anteriormentes)

## Secator

* [Repositório](https://github.com/freelabz/secator)

* Semelhante ao Sn1per

* A ideia é facilitar trabalho com diferentes ferramentas, compartilhando parâmetros entre diferentes ferramentas
  
  * (ex: aplicação1 usa --target, aplicação2 usa --t ... , secator busca evitar tantos parâmetros diferentes para execução mais rápida de conjunto de ferramentas)

* Possui ferramentas de scan de vulnerabilidades, descoberta de subdominios, crawlers ...

  * [Subfinder](https://github.com/projectdiscovery/subfinder) = Encontrar subdomínios e subpáginas (não encontrou tantos resultados quanto Sn1per -> usa ferramenta spider)

  * [h8mail](https://github.com/khast3x/h8mail) = Encontrar informações públicas relacionadas a algum usuário ou e-mail informado. Funcionamento simples, retornando serviços comuns (facebook, linkedin ...) que possuem o perfil informado. É possível ampliar a análise informando APIs de vazamentos, como o [Have I been pwned](https://haveibeenpwned.com/).

  * [wpscan](https://github.com/wpscanteam/wpscan) = Ferramenta para encontrar vulnerabilidades em sites wordpress. Útil pois coleta informações específicas do serviço wordpress, como plugins desatualizados, temas e versões. É possível integrar a ferramenta com a API do [WPScan](https://wpscan.com/api/), retornando assim além dos resultados, as vulnerabilidades associadas a cada problema encontrado.


## Nuclei

* Simples de usar

* [Informações de uso](https://blog.projectdiscovery.io/ultimate-nuclei-guide/)

* É uma ferramenta base, usada em outras ferramentas de escaneamento e análise de vulnerabilidades.

* Gera menos resultados em comparação a NMap e OpenVAS

* Tem lista de templates semelhantes aos scripts do nmap para buscar vulnerabilidades / informações especificas:

  * Ficam disponíveis em ```~/.local/nuclei-templates/```

  * São mais limitados em comparação ao Nmap e OpenVAS -> .YAML

    * Mandam requisições e comparam resultados (match da resposta)

      * Existe controle dos campos da requisição enviada

    * Não retorna sistema operacional

    * Mais de 8000 templates

    * Possível controlar taxa de sondagem, número de tentativas e outros parâmetros relacionados a performance

    * Possui templates com códigos javascript que executam tarefas mais elaboradas (ex: brute force)

* Possível ser usado para fazer [autenticação](https://docs.projectdiscovery.io/tools/nuclei/authenticated-scans)
  
  * [Exemplo de autenticação em discussão em fóruns](https://github.com/orgs/projectdiscovery/discussions/5262)

  * Necessário realizar mais testes - pouca informação online sobre a funcionalidade

### Inconsistências

* Em testes feitos localmente, a versão 3.2.9 apresenta inconsistências nos escaneamentos, em comparação a versão 3.2.4 (comparar arquivo [pkg/protocols/network/request.go](https://github.com/projectdiscovery/nuclei/blob/71628cc89734e8d426a2c734a4979a1429bc1462/pkg/protocols/network/request.go) entre as versões - adição de código para sincronização). [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.8bo47gww1ge8)

* Problemas encontrados com a versão 3.2.9:
  
  * Scans feitos em sequências apresentam resultados diferentes
  
  * Scans em urls diferentes para o mesmo IP apresentam resultados diferentes

## OpenVAS

* [Repositório](https://github.com/greenbone/openvas-scanner)

* Após instalar, cria servidor para ser acessado -> Interface gráfica simples que facilita operações e sumariza resultados

* Resultados salvos localmente (Postgres)

* Funcionalidades semelhantes aos demais escaneamentos -> Sistema operacional, CVEs, aplicações, informações SSH ...

* Porém, interface gráfica é útil para sumarizar e visualizar resultados

* Análises são longas, demora muito mais em comparação as demais ferramentas (10 minutos ... 1 hora) - ocorre pois openvas testa mais de 100.000 NVTs

  * Possível rodar scan *full and fast* para checar todos os NVTs disponíveis (demorado)

  * Scan no modo *cve* apenas checa o banner de resposta dos serviços em execução e então retorna todos os CVEs relacionados ao CPE encontrado (retorna vulnerabilidades do serviço, não quer dizer que exista na máquina)

* Retorna muitos resultados - vulnerabilidades possuem % de confiança (qualify of detection - foco em diminuir falsos positivos)

* Possibilidade de realizar autenticaçao durante escaneamento - ex: credenciais SSH

* Também consegue trabalhar com topologia (embora limitada em testes feitos -> **necessário testar melhor**)

* Plugins OpenVAS ``` /var/lib/openvas/plugins ```

* Escritos em linguagem de scripts .nasl (NASL - Nessus Attack Scripting Language)
* Tem controle dos pacotes enviados para testar vulnerabilidades

* Utiliza redis - chave / valor

  * Scripts possuem sistema de comunicação KB - Knowledge Base para compartilhar informações e salvar dados úteis entre plugins, coletando informações sobre serviços rodando e caso forem versões afetadas pela vulnerabilidade -> vulnerabilidade reportada

  * Diveros arquivos auxiliares existentes com funções usadas nos scripts (como checar versões, match de vulnerabilidades, fingerprint de respostas de serviços ...) - (pkg-lib-rpm.inc, gather-package-list.nasl)

* Existem scripts que operam em baixo nível, mandando e analisando resultados das requisições - embora a grande maioria faz checagem de versões no geral.

* [Diferença scans OpenVAS](https://forum.greenbone.net/t/what-is-the-difference-beween-the-openvas-default-scanner-and-the-cve-scanner/8555)

* [QOD](https://docs.greenbone.net/GCS-Manual/gcs/en/reports.html#quality-of-detection-concept)

  * QOD = 100 (exploit) -> 116 plugins
  * QOD = 99 (remote_vul) -> 647 plugins
  * QOD = 98 (remote_app) -> 227 plugins
  * QOD = 97 (package) -> 25958 plugins
  * QOD = 97 (registry) -> 1656 plugins
  * QOD = 95 (remote_active) -> 68 plugins
  * Demais plugins possuem QOD menor (muitos apenas verificam respostas do banner de resposta da requisição e fazem match de versão dos serviços rodando)

    * Se não existe patch level na resposta do banner, ou QOD menor ou plugin não retorna resultados

    * Alguns plugins possuem maior QOD porém dependem de autenticação (ex: SSH -> busca informações do SO e encontra lista de pacotes instalados, tornando a análise mais confiável)

    * [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.2564w1o1hucc)

  * Representa QOD de detecção e execução conforme o CPE existente, não qualifica o teste da vulnerabilidade em si

* [Informações OpenVAS cli](https://forum.greenbone.net/t/openvas-cli-commands/1428)

* [Reports OpenVAS multiplos CVEs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.szrquyb5saru)

## Netcat

* Permite comunicação entre dois dispositivos

* Permite executar shell em outro dispositivo

## Wafw00f - whatwaff

* Checar firewall

* ```wafw00f <url>```

* ```whatwaf -u <url>```

## Firewalk

* Checar regras de firewall

* Utiliza técnica firewalking. [Artigo](https://ieeexplore.ieee.org/abstract/document/5752565)

* Integrado com nmap (-1 é pra verificar todas as portas): ```sudo nmap --script=firewalk --traceroute --script-args=firewalk.max-probed-ports=-1 <ip>```

## Iptables

* Aplicação para definir regras de firewall

* Nmap consegue identificar as diferentes regras e também retornar o código ICMP definido

* [Guia](https://phoenixnap.com/kb/iptables-linux)

## Nessus

* Cria servidor semelhante openvas para fazer escaneamentos (demorado)

* Tem limitação de escaneamento, no máximo 16 hosts em uma rede.

* Por conta disso, não foi testado mais a fundo. Porém parece ser bem flexível em relação aos escaneamentos que podem ser executados

* Muitas opções de scan, porém menos informações rápidas sobre o banco de informações (em comparativo ao OpenVAS)

* Interface com melhor usabilidade e configuração

* Export mais personalizado em relação ao OpenVAS

## Defect Dojo

* [Repositório](https://github.com/DefectDojo/django-DefectDojo/tree/dev)

* Ferramenta para gerenciar vulnerabilidades, não encontra vulnerabilidades

* Oferece painel para visalizar, comentar e explorar vulnerabilidades encontradas
  
* Permite integração com pipelines para automatizar processo, integraçao com Jira ... -> Importante olhar formatos de arquivos para importação de cada ferramenta: [Integrações](https://defectdojo.com/integrations#categories)

* [Pipeline](https://www.youtube.com/watch?v=DLN1kNh_Ha0)

* Possui API para fazer automatizaçoes -> [Documentação - Defect dojo precisa estar rodando](http://localhost:8080/api/v2/oa3/swagger-ui/)

## Yara

* Criação de regras para identificar strings de malwares

* [Repositório com regras](https://github.com/Yara-Rules/rules/blob/master/cve_rules/CVE-2010-0805.yar)

* Faz análise de trafégo, buscando *matching* com regras estabelecidas

## Observações Nuclei x NMap x OpenVAS

* [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.zhyvjj1cbgte)

* A comparação entre as ferramentas gira muito em torno de Cobertura x Qualidade da detecção. O OpenVAS apresenta uma enorme quantidade de NVTs, cobrindo também uma enorme quantidade de CVEs em comparação as demais ferramentas. No entanto, muitas verificações são apenas de versão das aplicações em execução, não testando exatamente se a vulnerabilidade existe OU necessitando de um scan autenticado para obter informações do SO (como pacotes instalados), oferecendo maior segurança nas respostas. Já o Nuclei possui maior quantidade de templates, no entanto, suas verificações são muito rasas, fazendo apenas match de regex com a reposta. Já o NMap é o que apresenta maior qualidade de detecção de maneira geral, possuindo verificações mais profundas, realizando uma montagem cuidadosa das requisições e análise das respostas, porém apresenta muito poucos CVEs que são cobertos por seus scripts.

## Observações Metasploit x NMap x OpenVAS para diferentes CVEs

* [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.eura0e5jhttu)

* CVE 2014-9222 -> Misfortune Cookie. Cookie específico utilizado permite confundir o servidor que retorna a URL que foi passada como fonte na requisição. Ambas as ferramentas analisadas (NMap x OpenVAS x Metasploit) trabalham com o mesmo valor de cookie e o NMap e Metasploit realizam o exploit da vulnerabilidade, enquanto o OpenVAS realiza apenas a verificação e não é classificado diremente como exploit (QOD 99 e não existe menção a exploit na explicação do código). No entanto, ao analisar os processos realizados, ambos NMap e OpenVAS atuam de maneira idêntica, fazendo a requisição passando o cookie e então checando se na resposta existe o caminho passado na requisição (no caso, ambas as aplicações checam exatamente a mesma resposta retornada pelo servidor). Metasploit possui dois códigos de exploit, porém apenas 1 foi analisado pois usa o mesmo cookie das outras aplicações (possui ranking Normal). O funcionamento é semelhante, fazendo a requisição e verificação a saída. No entanto, o processo do metasploit é um pouco mais elaborado, como exemplo, testando diferentes caminhos possíveis, verificando diferentes códigos de resposta, além de retornar diferentes possibilidades para o teste (no caso, com a vulnerabilidade sendo: não detectada porém com o serviço analisado presente / desconhecida para o alvo / vulneravel / segura / parece vulneravel)

* [Slowloris](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.sdyhw7ew7g07) Atuação do metasploit não é semelhante a outras aplicações, como no caso do Nmap (discutido no link mencionado) que faz o exploit de maneira mais controlada, tendo alguns mecanismos de parada do ataque. Já o Metasploi realizada não somente a detecção, mas também o exploit, que é executado pelo maior tempo possível na máquina alvo - podendo continuar indefinidamente.

* CVE 2015-2208 -> Vulnerabilidade de injeção de código PHP. Nesse caso, a comparaçaõ foi feita entre o OpenVAS e o Metasploit. Ambos os códigos atuam de maneira bem semelhante, fazendo a requisição com algum comando a ser executado na porta com a aplicação php e checando se o retorno do comando está presente na resposta. O Openvas (QOD 100) realiza o teste com um comando simples - phpinfo() - e então verifica se está presente na resposta. A requisição é feita para uma lista de possíveis caminhos que o OpenVAS testa. Já o metasploit (ranking Excelent) utiliza a URL informada pelo usuário para fazer o exploit, tendo uma abordagem mais direta visto que já é conhecida a URL alvo, no entanto, necessita que o usuário tenha essa informação. Outro ponto é que o metasploit consegue realizar a checagem da vulnerabilidade com um comando simples - echo() - no entanto, consegue também realizar o exploit, executando algum payload que o usuário desejar - ex: reverse shell - ou algum outro payload presente na própria aplicação.

* [Informações no google docs sobre similaridade de Jaccard do Metasploit e OpenVAS](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.vukq5ytzf6f1). Análise realizada pois ambas as ferramentas possuem um número razoável (mais de 50) de testes envolvendo mais de um CVE. A ideia é analisar como é feita a detecção nesses casos e se as ferramentas operam de maneira semelhante. O gráfico apresenta mais valores na parte esquerda inferior (baixos coeficientes de Jaccard) mostrando que a interseção entre as ferramentas é baixa -> o que é válido, pois o metasploit atua fazendo checagens e exploits em baixo nível, enquanto o OpenVAS possui testes com muitos CVEs de uma só vez que realizam apenas verificações de versões por exemplo. 

  * Mais informações sobre os plugins do OpenVAS com diversos CVEs estão disponíveis no Google Docs: [link1](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.yxh5knqqsmp4), [link2](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.g0xvu37334ap)

## Comparação Nessus x OpenVAS para CVE-2016-2183

* CVE-2016-2183 -> Vulnerabilidade de cifras com força média (DES e 3DES usam 64 bits) que podem ter colisões dos blocos criptografados explorado. [Discussão no Google Docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.5q1au67s9x8h) Nessus e OpenVAS atuam de forma bem semelhante. Nessus pega as cifras da aplicação e então faz a verificação de acordo com a versão do serviço em execução (SSL / TLS) e checa a força das cifras. Existem diversas informações de cifras existentes na própria aplicação (+600 linhas) que são usadas para fazer a verificação da força da cifra do servidor, juntamente também a quantidade de bits utilizada. Nessus verifica diretamente 6 tipos de encapsulamento (SSL2-3, TLS1-1.1-1.2-1.3). OpenVAS trabalha de maneira semelhante, possui banco de cifras e descrições como o Nessus (quase 600 linhas). OpenVAS atua verificando diretamente 4 tipos de encapsulamento (SSL3, TLS1-1.1-1.2). Desse modo, mesmo com abordagens semelhantes, o Nessus atua de maneira mais robusta e verifica mais condições possíveis em comparação ao OpenVAS. Nos testes realizados em aplicações, o Nessus conseguiu identificar a vulnerabilidade em um host, enquanto o OpenVAS não. Como analisado ao longo do tempo, muito do código e dos procedimentos realizados por ambas as ferramentas são semelhantes e analisando a resposta das cifras utilizadas na máquina host, tanto o OpenVAS quanto o Nessus identificam as cifras utilizadas. Verificando [discussões em fóruns online](https://forum.greenbone.net/t/openvas-sometimes-does-not-detect-cve-2016-2183-sweet32/15844/2) o motivo para não detecção por parte do OpenVAS é por conta da porta da aplicação, que no caso, deveria ser uma porta com um aplicação HTTP (que não era a situação da máquina host).

## Comparação vulnerabilidades sem CVE associado

* Brute Force VNC = A vulnerabilidade é associada a possibilidae de login via força bruta no protocolo VNC (sem CVE associado pois não é falha de software, mas sim falha de configuração no dispositivo analisado). OpenVAS (QOD 95) e NMap atuam de maneira bem semelhantes, fazendo as etapas de Conexão no Servidor -> Handshake Inicial -> Checagem dos tipos de autenticação -> Teste de senhas. No processo, ambas as ferramentas possuem salvos os tipos possíveis de autenticações aceitas no protocolo, cuidam das etapas de criptografia e verificação de versões para identificar os tipos de autenticação disponíveis. Vale destacar que o NMap é um pouco mais completo e salva diferentes possibilidaes de autenticação. No cenário testado, ambas as ferramentas chegaram ao mesmo resultado mostrando que a máquina alvo não possuia métodos de autenticação. [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.4faeogtxf92f)

* Weak MAC algorithms SSH = A vulnerabilidade é associada a algoritmos fracos utilizados em uma máquina (sem CVE associado pois operador da máquina não deve utilizar algoritmos fracos). Tanto OpenVAS, Nuclei e Nessus fazem a verificação dessa vulnerabilidade, atuando de maneira bem semelhanteverificando os tipos de algoritmos aceitos e reportando caso algoritmos MD5 ou de 96 bits são utilizados. Vale destacar que o OpenVAS é o único que verifica o caso de algoritmos de 64 bits sendo utilizados. [Discussão no google docs](https://docs.google.com/document/d/1mEUaCtZ0zb9yBUhmnN_t0aM5mlOAk0zCI4wCdN94VY8/edit?pli=1#bookmark=id.4faeogtxf92f)

## Comparação funcionalidades x Aplicações

|         | SO | MAC | Ports / Aplication / Version | CVE | CVSS | VPR | Show if exploit exists | Time to scan | Export Report | Topology   | Scan control | Last reboot | Scan TCP/UDP | CVE Solution | Authentication | WAF |
|:------- |:--:|:---:|:----------------------------:|:---:|:----:|:---:|:----------------------:|:------------:|:-------------:|:----------:|:------------:|:-----------:|:------------:|:------------:|:--------------:|:---:|
| NMap    | X  |X    | X                            | X   | X    |     | X                      | Fast         | XML           | Zenmap*    | High         | X           | X            |              |                | X   |
| Sn1per  | X  |X    | X                            | X   | X    |     | X                      | Fast         | XML / HTML    |            | High         |             | X            |              |                | X   |
| Nuclei  | X  |X    | -                            | X   | X    |     | X                      | Fast         | JSON / MD     |            | High         |             |              |              | X              | X   |
| OpenVAS | X  |X    | X                            | X   | X    |     | X                      | Slow         | GUI / XML     | -          | High         |             | X            | X            | X              |     |
| Nessus  | X  |X    | X                            | X   | X    | X   | X                      | Slow         | GUI           |            | High         |             |              | X            | X              |     |

### Observações

* Scan Control = Personalizar escaneamento (Ex: testar vulnerabilidades especificas, testar só aplicações WEB, alterar modos escaneamentos ...)

* Nessus = Versão gratuita é limitada a 16 escaneamentos.

* Zenmap = Para usar topologia com NMap, importante ativar opção **--traceroute** ao fazer o escaneamento.

* Sn1per gera relatorio HTML - porém é dump da saída do terminal. Gera também saídas xml, porém são as saídas XML do Nmap.

* [VPR](https://pt-br.tenable.com/blog/what-is-vpr-and-how-is-it-different-from-cvss) = Métrica da Tenable (empresa do Nessus) -> Mais completa do que CVSS.

* OpenVAS possui topologia, porém só mostra dispositivos escaneados ligados a máquina de onde o escaneamento foi feito. Não sei se da pra melhorar essa parte.

* Nuclei mostra algumas aplicações, mas não especifica portas ou versões.

* Em testes em uma máquina, Nuclei dectectou WAF - usa ferramenta WHATWAF - , porém Sn1per - possui ferramenta para isso WAFW00F - não detectou, nem o Nmap - possui script que integra WAFW00F

* NMap e Sn1per possui integração com firewalk

* Last reboot = Não é tão preciso, erra por alguns dias.

-------------

## Funcionalidades adicionais de ferramentas pagas em comparação a versões gratuitas

|         | Description | Support | Integrations | Team | Performance | Reports | Interface | Vulnerabilities | Updates | Backup |
|:------- |:--:|:--:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Nuclei | Project Discovery has pro and enterprise plans | By chat | External services like Slack, Github and Azure in addition to its own API | Team workspace and API | More powerfull scans | JSON, PDF, CSV | - | - | - | - |
| Metasploit | Rapid7 has the Pro version of Metasploit in addition to other products and services for sale | - | It has its own API and external services, like Nmap and OpenVAS | - | - | More support to reports | Web interface | More exploits and automated workflows to check vulnerabilities | - | - |
| Nmap | The Nmap Organization sells OEM licenses to integrate Nmap software with other products | Commercial Support | - | - | - | - | - | - | Automatic | - |
| OpenVAS | Greenbone offers enterprise and Cloud services | Assured with SLA | It has its own API and external services like  Cisco FireSight, Nagios ... | - | Optimized for hardware | Free version already supports different types of reports | Free version already has a web interface | Database (Enterprise Feed) with vulnerabilities to enterprise products and specific compliance checks (healthcare, finances ...). 30% more NVTs | Automatic | Manual or automatic |

### Observações

* \- = No information

* [NVTs openvas](https://community.greenbone.net/uploads/default/original/2X/a/abe9acece80fdd9a03427b81692830b6e23824d8.png)

------------

* Outras aplicações para serem checadas

  * VNStat
  * EtherApe
  * Setop
  * Bettercap
  * projectdiscovery’s cvemap
  * <https://www.kali.org/tools/theharvester/>
  * <https://github.com/tomac/yersinia>
  * nikto
  * blackWidow
  * Sistemas de gerência - ArcherySec, <https://github.com/yogeshojha/rengine>, <https://github.com/infobyte/faraday>

-------------

### Procolos camadas 2 - Identificação de dispositivos em rede

* CDP

  Cisco Discovery protocol. Ajuda a descobrir roteadores e vizinhos
  
  Rodar comandos dentro do switch para descobrir dispositivos vizinhos

* LLDAP

  Link layer discovery protocol. Mesma ideia do CDP.
  [Rodar comandos dentro do switch](https://www.youtube.com/watch?v=334AVAjhs04)
  
