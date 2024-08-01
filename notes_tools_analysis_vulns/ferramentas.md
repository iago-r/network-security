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

* Trabalha com módulos pesquiso com ```search```

  * ex: ```search type:<ex: exploit> platform:<ex: windows>``` para usar exploit -> preciso associar a payload (carrega exploit)

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

  * Subfinder = Encontrar subdomínios e subpáginas (não encontrou tantos resultados quanto Sn1per - usa ferramenta spider)

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

## Comparação funcionalidades x Aplicações

|         | SO | MAC | Ports / Aplication / Version | CVE | CVSS | VPR | Show if exploit exists | Time to scan | Export Report | Topology   | Scan control | Last reboot | Scan TCP/UDP | CVE Solution | Authentication | WAF |
|:------- |:--:|:---:|:----------------------------:|:---:|:----:|:---:|:----------------------:|:------------:|:-------------:|:----------:|:------------:|:-----------:|:------------:|:------------:|:--------------:|:---:|
| NMap    | X  |X    | X                            | X   | X    |     | X                      | Fast         | XML           | Zenmap*    | High         | X           | X            |              |                | X   |
| Sn1per  | X  |X    | X                            | X   | X    |     | X                      | Fast         | XML / HTML    |            | High         |             | X            |              |                | X   |
| Nuclei  | X  |X    | -                            | -   | -    |     | X                      | Fast         | JSON / MD     |            | High         |             |              |              | X              | X   |
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
  
