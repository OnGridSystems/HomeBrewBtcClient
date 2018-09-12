## Description

This is not fully compatible bitcoin node. For now it is minimal bitcoin protocol implementation.
Currently it work as SPV node and scan blockchain for certain addresses and stop after that.
Now under development, so more functions will added later.

### Installation
Pull or download this repository. Then go into HomeBrewBtcClint directory  
Install new virtual environment:

```
$ python3 -m venv venv
$ source venv/bin/activate
```

Install requirements
```
$ pip install -r requirements.txt
```

### Run
To run default testcase
```
$ python run.py
```

A single connection to random chosen public testnet node will created and scan for predefined address will be started.  
After reach of last known block the process automatically stop showing results.

If you want to test it on main net with your own addresses:  
Go to the node/settings.py and change WORKING_NET value from 'testnet' to 'main'  
To change the set of addresses to scan, go into run.py. Here you can also change peer ip to connect.


If you do not want the process to stop when you reach the highest block:  
Go into node/protocol.py and comment this string
```
self.finish()
```
After that the process will run infinite. Or until exception occurs.
