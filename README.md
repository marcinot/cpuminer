# biblepay cuda/gpu miner

This is my cuda gpu implementation of POBH miner (based on external cpuminer and code from ccminer). 

## Compilation

1. Install Ubuntu 18.04 LTS (http://releases.ubuntu.com/18.04/)

2. Install nvidia drivers and CUDA toolkit
```
sudo apt update
sudo apt install nvidia-driver-390
sudo apt install nvidia-cuda-toolkit
sudo reboot
```
You can also install newer cuda version from nvidia.

3. Check if its correctly installed
```
nvcc --version
nvidia-smi
```

3. Install dependencies
```
sudo apt install libcurl4-openssl-dev
sudo apt install libgmp-dev
```

4. Clone and compile
```
git clone https://github.com/marcinot/cpuminer.git
cd cpuminer
./compile.sh
```

If you have errors try changing nvcc path in algo/cuda/Makefile or cuda libraries path in Makefile.am. Currently this paths are hardcoded.


5. Test
```
./run.sh
```

You should get something like this (real example for one GTX 750)

```
KJV Loaded
Using bbpminer version 1009

solo mining 0
[2020-01-20 00:29:47] 1 miner threads started, using 'pobh' algorithm.
[2020-01-20 00:29:47] Starting Stratum on stratum+tcp://5.135.183.202:3016
[2020-01-20 00:29:48] Stratum requested work restart
[2020-01-20 00:29:51] thread 0: 2097153 hashes, 719.74 khash/s
[2020-01-20 00:30:08] thread 0: 21572355 hashes, 1261 khash/s
[2020-01-20 00:30:09] accepted: 1/1 (100.00%), 1261 khash/s (yay!!!)
[2020-01-20 00:30:09] Stratum requested work restart
[2020-01-20 00:30:09] thread 0: 786433 hashes, 1249 khash/s
[2020-01-20 00:30:36] Stratum requested work restart
[2020-01-20 00:30:36] thread 0: 35160065 hashes, 1261 khash/s
[2020-01-20 00:30:40] Stratum requested work restart
[2020-01-20 00:30:40] thread 0: 4947969 hashes, 1259 khash/s
[2020-01-20 00:31:00] thread 0: 24126554 hashes, 1255 khash/s
[2020-01-20 00:31:00] accepted: 2/2 (100.00%), 1255 khash/s (yay!!!)
[2020-01-20 00:31:00] Stratum requested work restart
[2020-01-20 00:31:00] thread 0: 131073 hashes, 1137 khash/s
```

## Use

Configure parameters in run.sh file.

1. Set threads to number of installed GPUs
2. Set user, pool, password to your own
3. Use high difficulty ports 

Check pool settings here http://sunpool.whitewalr.us/getting_started 

## Limitations

- Probably will work only for a while (until hard fork) :-)
- Doesn't work on old nvidia cards (required SM35 architecture or highier, check this http://arnon.dk/matching-sm-architectures-arch-and-gencode-for-various-nvidia-cards/)



