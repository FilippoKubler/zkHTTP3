# zkHTTP3
### A Zero-Knowledge Middlebox for Secure FaaS using HTTP/3

# Setup Instructions
! Tested on Ubuntu 22.04
- Clone the repository
```bash
  git clone git@github.com:FilippoKubler/zkHTTP3.git
```

- Run the ```setup``` script to initialize the project
```bash
cd ./zkHTTP3 && ./setup
```
The script executes these steps:
> - Install all the Requirements
> ```bash
> sudo apt install build-essential gcc-9 g++-9 cmake git libgmp3-dev libprocps-dev python3-markdown libboost-program-options-dev libssl-dev python3 pkg-config python3-pip python-is-python3 tshark openjdk-17-jre-headless apt install openjdk-17-jdk-headless
> ```
> libprocps-dev cannot be installed in Ubuntu 24.04

> - Install python libraries for aioquic
> ```bash
> pip install aioquic uvloop wsproto requests pyshark pycryptodome psutil flask
> python3 -m Cryptodome.SelfTest
> ```

> > **If building on Ubuntu >20.04** you must set GCC-9 and G++-9 as default versions:
> > ```bash
> > sudo ln -s -f /usr/bin/gcc-9 /usr/bin/gcc
> > sudo ln -s -f /usr/bin/g++-9 /usr/bin/g++
> > ```
> > After building, you can revert this change by linking back the previous default GCC and G++ versions.

> - Move to libsnark directory and create the build folder 
> ```bash
> cd libsnark && mkdir build && cd build
> ```

> - Compile libsnark with the preferred compilation flags
> ```bash
> cmake <flags> ..
> ```
> Tested flags: ```-DMULTICORE=ON``` and ```-DUSE_PT_COMPRESSION=OFF```
> then 
> ```bash
> make
> ```

> - Generate the certificates for the Client and Server
> ```bash
> openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -keyout ca.key -out ca.pem -subj "/O=http3-client Certificate Authority/"
> openssl req -out cert.csr -new -newkey rsa:2048 -nodes -keyout priv.key -subj "/O=http3-client/"
> openssl x509 -req -sha256 -days 3650 -in cert.csr  -out cert.pem -CA ca.pem -CAkey ca.key -CAcreateserial -extfile <(printf "subjectAltName=DNS:127.0.0.1")
> ```

> - Locate where the python libraries are installed (usually ```/usr/local/lib/python3.10/dist-packages/```) and substitute the aioquic folder
> ```bash
> rm -rf aioquic
> git clone https://github.com/FilippoKubler/aioquic.git
> ```


# Run the project

#### Open 4 cli shells:

- Move to ```https-client``` folder and run the following command
```bash
cd ./http3-client
python http3-client.py --ca-certs "certs/ca.pem" --cipher-suites "AES_128_GCM_SHA256" -l "keys" -q "quic-log" -v -i -k -d HTTP3 https://127.0.0.1:4433/function/figlet
```

- Move to ```middlebox``` folder and run the following command
```bash
cd ./middlebox
python middlebox.py
```

- Move to ```middlebox``` folder and run the following command
```bash
cd ./middlebox
python capture.py
```

- Move to ```https-server``` folder and run the following command
```bash
cd ./http3-server
python3 http3-server.py -v -c certs/cert.pem -k certs/priv.key -q quic-log -l keys
```


# Execute Tests

#### Live Test:

- Move to ```https-client``` folder and run the following command
```bash
cd ./http3-client
python http3-client.py --ca-certs "certs/ca.pem" --cipher-suites "AES_128_GCM_SHA256" -l "keys" -q "quic-log" -t -r 1 -v -i -k -d HTTP3 https://127.0.0.1:4433/function/figlet
```

- Move to ```middlebox``` folder and run the following command
```bash
cd ./middlebox
python middlebox.py -t -r 1
```

- Move to ```middlebox``` folder and run the following command
```bash
cd ./middlebox
python capture.py
```

- Move to ```https-server``` folder and run the following command
```bash
cd ./http3-server
python3 http3-server.py -v -c certs/cert.pem -k certs/priv.key -q quic-log -l keys
```


#### Signle Function Tests:

- Move to ```middlebox``` folder and run the following command
```bash
cd ./middlebox
python trackers.py
```

# Use MPS IDE
- Install [MPS 3.3.5](https://www.jetbrains.com/mps/download/previous.html)
- Open Project, select the MPS/xjsnark_mod directory from this repo
- If in the "Project" left sidebar xjsnark.runtime and xjsnark.sandbox give error:
    - xjsnark.runtime: Right click -> module properties
      - On the Common tab, select javaclasses on Add Model Root and select the folder containing the .class files of the xjsnark backend (should be in xjsnark_decompiled/backend_bin_mod), then remove the folder giving error
      - On the right side of the window select the just-added folder and click on Models
      - On the Java tab, add as library the same folder added in the previous step (as java_classes), then remove the folder giving error.
    - xjsnark.sandbox: Right click -> module properties
      - On the "Output Path" section, select any folder to put the java files. For example select the MPS Generated Code folder.
- To edit policies, open the xjsnark.sandbox section on the left sidebar, under "PolicyCheck" you find the three String / Merkle / Merkle Token policies for HTTP traffic
- To compile the policies, right click on either the whole xjsnark.sandbox or the single PolicyCheck module and select "Make Model" or "Make Solution". The generated java files should be in the "MPS Generated Code" folder.

- Compile Policies into java code after some modification
```bash
cd ../xjsnark_decompiled/ && javac -d xjsnark_bin/ -cp backend_bin_mod:xjsnark_bin/ xjsnark_src/xjsnark/*/*.java
```
Remember to generate again the key pair by deleteing the ```provKey.bin``` file from the ```/middlebox/files``` folder.