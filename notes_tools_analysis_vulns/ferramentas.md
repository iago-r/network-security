# Anotações gerais sobre ferramentas do kali linux

* sqlmap

  Explora falhas de banco de dados - ex: sql injection

  ```sqlmap -u <url>```
  
  ```sqlmap -r <arquivo raw>```

  comando ```--dbs``` -> vejo nome bancos

  posso ver informações específicas do banco: ```-D <banco> --tables```

  depois ```-D <banco> -T <tabela> --columns```

* Wifite

  vejo redes wifi disponiveis e consigo conectar se tiver dispositivos usando

* Netdiscover

  ```netdiscover -i <interface> -r <ip / mascara>```

  vejo info de dispositivos na rede

* Nmap

  Usar parâmetro ```-v``` para aumentar verbosidade

  ```nmap -sP <ip/mascara>```
 retorna todos os ips da rede (só faço ping)

  ```nmap -sL <ip/mascara>```
    retorna lista dispositivos sem scan de portas
  
  ```nmap -sT <ip>``` (T = TCP, fullscan)
  retorna portas abertas e o que esta rodando
  (pode ser considerado como ataque, quem adm a rede consegue perceber scan)
  
  ```nmap -sS -p <portas separadas , > <ip>``` (S = stealthy)
 igual comando acima, mas não é considerado ataque
  
  ```nmap -p <porta> <ip>```
 faço consulta se determinada porta está aberta, não é considerado ataque
  
  ```sudo nmap -sT -p <portas separadas , > <ip/mascara>```
 vejo detalhes das portas
  
  ```sudo nmap -O <ip>```
 vejo sistema operacional máquina (retorna % de chances de acerto para diferentes sistemas)
  
  ```nmap -sV <ip>```
 vejo mais detalhes de escaneamentos, portas abertas, versões de serviços. Analise extensiva e agressiva
  
  ```nmap -A <ip>``` (A=agressive)
 sistema operacional, versão protocolos, portas abertas, traceroute... -> todas funcoinalidades.
  
  ```nmap ... -D <ip_decoy>``` (D = decoy **pesquisar mais**)
  
  nmap possui scripts para automatizar varreduras

   pasta ```/usr/share/nmap/scripts```
   [Guia scripts](https://www.ninjaos.org/user_guides/nmap_scripts.pdf)
  * vulns especificas
  * listar cves
  mostra exploits
  * ssl injection
  * firewall (firewalk e waf)

  uso com ```nmap --script <nome script> <<<parametros>>>``` ( se aperto enter mostra progresso do script)

  possível aumentar quantidade de scripts do nmap baixando outros já prontos

  atualizo com ```nmap --scrip-updated```

  parametro: ```-oX <nome_arquivo_xml_saida>``` é gerado um arquivo XML com os resultados -> útil para parser e uso no zenmap.

  * com isso é possível transformar em HTML ```xsltproc <arquivo_xml_entrada> -o <arquivo_hmtl_saida>```

  [Zenmap](https://nmap.org/book/zenmap.html) -> interface gráfica para o nmap
  
  * Útil -> Gerar topologia da rede, facilita identificação visual dos dispositivos e sumariza informações.

* Wireshark

  monitoro trafego

  vejo pacotes enviados e informações

  se não tem https, fácil de ver conteudo trocado entre cliente / server
  
  tem diferentes 'profiles' -> configurações
  
  mostra timestamp de conexão / requisão de dispositivos
  
  consigo exportar escaneamento para csv

* Metasploit

  Versão de código aberto ou comercial

  ```msfconsole``` abre terminal do metasploit

  trabalha com módulos pesquiso com ```search```

  ex: ```search type:<ex: exploit> platform:<ex: windows>```
  para usar exploit -> preciso associar a payload (carrega exploit)

* Sn1per

  attack surface manangment
  
  Usa NMap para enumerar portas, reconhecimento, scripts em portas abertas.
  
  Usa modulos de exploração do Metasploit
  
  Utiliza outras ferramentas para analise e exploracao (Smuggler - requisicoes HTTP, gospider - crawler, WAF - firewall ...)

   [Ferramentas integradas pelo Sn1per](https://github.com/1N3/Sn1per/wiki/Plugins-&-Tools)
  
  --> [Descrição inicial da ferramenta](https://mindsetsecurity.wordpress.com/2018/04/24/sn1per/)
  
  --> [Repositorio Sn1per](https://github.com/1N3/Sn1per?tab=readme-ov-file)

  Ferramenta completa -> faz várias análises de uma só vez. Busca serviços, portas, versões, sistemas operacionais, checa vulnerabilidades, emails ... -> gera dump com saída das ferramentas utilizadas

  Gera várias pastas com os resultados obtidos.
  
   Sumariza informações na pasta ```/usr/share/sniper/loot/workspace```

  ```sniper -t <ip ou rede>``` -> analise normal

  ```sniper -t <ip ou rede> -m discover``` -> exploração de rede

  * Consigo ver informações de ssh -> se aceita autenticação por senha
  * Serviços
  * Retorna vulnerabilidades, cabeçalhos web, ips de uma rede ...
  * Tem sobreposiço de informaçoes (subferramentas acabam gerando resultados já vistos anteriormentes)

* Nuclei

  Simples de usar

  Gera menos resultados em comparação a NMap e OpenVAS

  Tem lista de templates semelhantes aos scripts do nmap para buscar vulnerabilidades especificas

   Ficam disponíveis em ```~/.local/nuclei-templates/```

  Nao retornou sistmea operacional

  É uma ferramenta base, usada em outras ferramentas de escaneamento e análise de vulnerabilidades.

  Possível ser usado para fazer autenticação

  [Repositorio com informações de uso](https://blog.projectdiscovery.io/ultimate-nuclei-guide/)

* OpenVAS

  [Repositório](https://github.com/greenbone/openvas-scanner)

  Após instalar, cria servidor para ser acessado -> Interface gráfica simples que facilita operações e sumariza resultados
  * Resutlados salvos localmente (Postgres)

  Funcionalidades semelhantes aos demais escaneamentos -> Sistema operacional, CVEs, aplicações, informações SSH ...
  * Porém, interface gráfica é útil para sumarizar e visualizar resultados

  Análises são longas, demora muito mais em comparação as demais ferramentas (10 minutos ... 1 hora)

  Retorna muitos resultados - vulnerabilidades possuem % de confiança (qualify of detection - foco em diminuir falsos positivos)

  Possibilidade de realizar autenticaçao durante escaneamento - ex: credenciais SSH

  Também consegue trabalhar com topologia (embora limitada em testes feitos -> **necessário testar melhor**)

* Netcat

  Permite comunicação entre dois dispositivos

   Permite executar shell em outro dispositivo

* Wafw00f - whatwaff

  Checar firewall

  ```wafw00f <url>```

  ```whatwaf -u <url>```

* Firewalk

  Checar regras de firewall

  UUtiliza técnica [firewalking](https://ieeexplore.ieee.org/abstract/document/5752565)

  Integrado com nmap (-1 é pra verificar todas as portas): ```sudo nmap --script=firewalk --traceroute --script-args=firewalk.max-probed-ports=-1 <ip>```

* Nessus

  Cria servidor semelhante openvas para fazer escaneamentos (demorado)

  tem limitação de escaneamento, no máximo 16 hosts em uma rede.

  * Por conta disso, não foi testado mais a fundo. Porém parece ser bem flexível em relação aos escaneamentos que podem ser executados

* [Defect Dojo](https://github.com/DefectDojo/django-DefectDojo/tree/dev)

  Ferramenta para gerenciar vulnerabilidades, não encontra vulnerabilidades

  Oferece painel para visalizar, comentar e explorar vulnerabilidades encontradas
  
   Permite integração com pipelines para automatizar processo, integraçao com Jira ... -> Importante olhar formatos de arquivos para importação de cada ferramenta [Integrações](https://defectdojo.com/integrations#categories)

   Possui API para fazer automatizaçoes -> [Documentação - defect dojo precisa estar rodando](http://localhost:8080/api/v2/oa3/swagger-ui/)

* Yara

  Criação de regras para identificar strings de malwares

  [Repositório com regras](https://github.com/Yara-Rules/rules/blob/master/cve_rules/CVE-2010-0805.yar)

  Faz análise de trafégo, buscando *matching* com regras estabelecidas

## Comparação funcionalidades x Aplicações

|         | SO | MAC | Ports / Aplication / Version | CVE | CVSS | VPR | Show if exploit exists | Time to scan | Export Report | Topology   | Scan control | Last reboot | Scan TCP/UDP | CVE Solution | Authentication | WAF |
|:------- |:--:|:---:|:----------------------------:|:---:|:----:|:---:|:----------------------:|:------------:|:-------------:|:----------:|:------------:|:-----------:|:------------:|:------------:|:--------------:|:---:|
| NMap    | X  |X    | X                            | X   | X    |     | X                      | Fast         | XML           | Zenmap*    | High         | X           | X            |              |                | ?   |
| Sn1per  | X  |X    | X                            | X   | X    |     | X                      | Fast         | -             |            | High         |             | X            |              |                | ?   |
| Nuclei  | X  |X    | -                            |     |      |     | X                      | Fast         | JSON / MD     |            | High         |             |              |              | X              | X   |
| OpenVAS | X  |X    | X                            | X   | X    |     | X                      | High         | GUI / XML     | -          | High         |             | X            | X            | X              |     |
| Nessus  | X  |X    | X                            | X   | X    | X   | X                      | High         | GUI           |            | Medium       |             |              | X            | X              |     |

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

-------------

### Procolos camadas 2 - Identificação de dispositivos em rede

* CDP

  Cisco Discovery protocol. Ajuda a descobrir roteadores e vizinhos
  
  Rodar comandos dentro do switch para descobrir dispositivos vizinhos

* LLDAP

  Link layer discovery protocol. Mesma ideia do CDP.
  [Rodar comandos dentro do switch](https://www.youtube.com/watch?v=334AVAjhs04)
  
