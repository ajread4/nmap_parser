# NMAP Parser
Simple parser for NMAP output using Python3. 

## Install 
```
$ git clone https://github.com/ajread4/nmap_parser.git
$ cd nmap_parser
$ pip install -r requirements.txt
```
## Usage 
```
$ python3 nmap_parse.py -h
usage: nmap_parse.py [-h] file output_directory

nmap_parse - a capability to extract key port and IP information from nmap scans

positional arguments:
  file              specify the input nmap scan (needs to be either .nmap, .xml, or .gnmap extension)
  output_directory  specify output directory for key port and IP information from scans

optional arguments:
  -h, --help        show this help message and exit
```

## Example Usage 
1. Parse a GNMAP file and output to ```outputdirectory/```. 
```
$ python3 nmap_parse.py ./test_data/nmap_test.gnmap outputdirectory
[+] Requested Parsing of GNMAP file
$ ls outputdirectory/
1099_open.txt  192.168.78.132_open.txt  2121_open.txt  25_open.txt    513_open.txt   5900_open.txt  80_open.txt
111_open.txt   192.168.78.133_open.txt  21_open.txt    3306_open.txt  514_open.txt   6000_open.txt  8180_open.txt
139_open.txt   192.168.78.2_open.txt    22_open.txt    445_open.txt   53_open.txt    6667_open.txt
1524_open.txt  2049_open.txt            23_open.txt    512_open.txt   5432_open.txt  8009_open.txt
$ $ cat outputdirectory/445_open.txt
192.168.78.133:445
$ cat outputdirectory/53_open.txt
192.168.78.2:53
192.168.78.133:53
$ cat outputdirectory/192.168.78.133_open.txt
21
22
23
25
53
80
111
139
445
512
513
514
1099
1524
2049
2121
3306
5432
5900
6000
6667
8009
8180
```
2. Parse a XML file and output to ```outputdir/```. 
```
$ python3 nmap_parse.py ./test_data/nmap_test.xml outputdir
[+] Requested Parsing of XML file
$ ls outputdir/
1099_open.txt  192.168.78.133_open.txt  21_open.txt  3306_open.txt  514_open.txt   6000_open.txt  8180_open.txt
111_open.txt   192.168.78.2_open.txt    22_open.txt  445_open.txt   53_open.txt    6667_open.txt
139_open.txt   2049_open.txt            23_open.txt  512_open.txt   5432_open.txt  8009_open.txt
1524_open.txt  2121_open.txt            25_open.txt  513_open.txt   5900_open.txt  80_open.txt
$ cat outputdir/23_open.txt
192.168.78.133:23
$ cat outputdir/139_open.txt
192.168.78.133:139
$ cat outputdir/192.168.78.2_open.txt
53
```

## Repository Structure 
- ```test_data/```: example NMAP files to test the parser. 
- ```requirements.txt```: python packages required for usage. 

## Author
All code written by AJ Read (ajread4). 
