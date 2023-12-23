# BEKMP: A Blockchain-Enabled Key Management Protocol for Underwater Acoustic Sensor Networks

The repository hosts the HOMQV and ECQV protocols' implementation and benchmarks, utilizing the [micro-ECC](https://github.com/kmackay/micro-ecc/) library as detailed in the BEKMP paper. To execute this code, ensure the blockchain network from https://github.com/juvebogdan/BEKMP-Blockchain-Platform is operational, along with its accompanying API. Once the blockchain component is set up, proceed with the following steps:

## Compile
```bash 
mkdir build
cd build
cmake ..
make
```

# Run test
```bash
./BEKMP
```
