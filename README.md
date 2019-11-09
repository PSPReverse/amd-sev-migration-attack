## Introduction
This repository contains a proof-of-concept implementation of the "Migration Attack" proposed in our paper:

*Insecure Until Proven Updated: Analyzing AMD SEV's Remote Attestation*

The paper will be presented at the [*26th ACM Conference on Computer and Communications Security*](https://sigsac.org/ccs/CCS2019/) (CCS'19) in London.
You can find a pre-print version of the paper [here](https://arxiv.org/abs/1908.11680).

In the paper we show that we were able to obtain the `chip-endorsement-key` (CEK) from AMD EPYC cpus of the Naples series.
This key plays a central role in the trust model of the *Secure Encrypted Virtualization* technology from AMD.
Based on the key extraction, we propose attacks against AMD SEV protected virtual machines that allow an attacker to fully circumvent the protection granted by the SEV technology.

Please refer to our [paper](https://arxiv.org/abs/1908.11680) for the details.

This proof-of-concept implementation consists of the following files:

Filename | Description
-------- | -----------
`Readme.md` | This file.
`launch-qemu.sh` | Script used to launch the VM.
`migrate.py` | Script to start VM migration.
`decrypt.py` | Script to decrypt exported VM memory.
`keys/pdh_priv.pem` | PDH private key that was used to initiate VM migration of the `vm.mem` image.
`keys/pdh_remote.cert` | The PDH certificate of the target host.

The image of encrypted guest memory used for this proof-of-concept can be found [here](TODO).


## Background
The ability to migrate virtual machines from one host to another is a crucial feature in cloud-computing.
It allows to ensure e.g. the availability of virtual machines in case of failure in the host system.
Migration of virtual machines requires to copy the memory content from the source host to the destination host. 
With the *Secure Encrypted Virtualization* (SEV) technology, the memory cannot be simply moved to another host as it is encrypted with a key that never leaves the secure processor (PSP) of the host.
To allow migration with SEV in place, AMD introduced a migration scheme that allows to migrate encrypted virtual machine memory using dedicated transport keys.
While the untrusted hypervisor is still responsible to copy the memory, it is still protected using keys known only by the trusted secure processors of the source and destination of the migration.

To perform the migration, the following steps need to be performed (simplified):


1. The target of the migration needs to provide a valid certificate chain
  ```
  PDH_target -> PEK -> CEK -> ASK -> ARK
  ```
2. The secure processor of the source host will verify the certificate chain.
3. If successful, the secure processor will derive a *shared secret* using the provided *platform-diffie-hellman-key* (PDH). The PDH_source of the source platform is exported to the target platform to derive the same shared key.
4. The source platform will derive several keys from the shared secret using a key derivation function:
    * The *master-secret*: KDF(*shared-secret*)
    * The *key-encryption-key* (KEK): KDF(*master-secret*)
    * The *key-integrity-key* (KIK): KDF(*master-secret*)
5. The source platform generates *transport keys*: 
    * The *transport-integrity-key* (TIK)
    * The *transport-encryption-key* (TEK)
6. The source platform encrypts the TEK and TIK using the KEK and computes a MAC using the KIK. This process is referred to as *key wrapping*.
7. The source platform re-encrypts the VM's memory using the TEK and exports the encrypted memory and the wrapped keys to the hypervisor.
8. Using the PDH_source, the target platform can derive the same keys as in Steps 2 to 5.
9. Using the derived KEK, the target platform can decrypt the TIK and TEK and then decrypt the virtual machines memory.

For details, please refer to the [AMD SEV API 0.22](https://developer.amd.com/wp-content/resources/55766.PDF) specification, Appendix A.

## Migration Attack
Using an extracted `chip-endorsement-key`, an attacker can create a valid certificate chain:
  ```
  PDH_target -> PEK -> CEK -> ASK -> ARK
  ```
and pose as a target for migration.
To that end, the attacker creates the certificate chain and derives the KIK and KEK as described in the Steps 3 to 4.
Now the attacker can decrypt the exported virtual machine memory using the decrypted TEK.

For the migration attack to work, the target host does not need to contain any security issues.
As long as the guest policy allows migration, an attacker can extract it's memory content. 
A valid CEK extracted from an arbitrary AMD Epyc CPU is sufficient to mount this attack.

We have successfully performed this attack on a virtual machine with SEV protection in place.
We were able to extract the full memory of the virtual machine including keyboard inputs that were entered over an SSH protected remote console.
The target host was running the latest SEV firmware at the time of writing (SEV API 17. Build 22).
We would like to emphasize that we do NOT require any security issues to be present in either the target host nor in the target virtual machine. 
Our attack does NOT depend on any specific guest software or services running inside a guest.
To the best of our knowledge, all Epyc systems of the AMD EPYC Naples (Zen1) are affected.

While we don't see any obstacles to make this attack work on newer, Zen2 based systems, we are not aware of any firmware issues in that allow to extract a *chip-endorsement-key* from Zen2 based systems.
The extracted CEK from Zen1 systems is not accepted by Zen2 systems.

The scripts in this repository contain the exact steps necessary to perform the migration attack on an SEV protected virtual machine. 
We also include an encrypted guest memory image and the corresponding PDH private key that allows to decrypt the memory. 
The required Steps are explained in the [Usage](#usage) Chapter.

## Mitigations
SEV allows to prevent the migration of virtual machines using a policy that is defined by the guest owner. 
Using the `NOSEND` bit if the guest policy (See [AMD SEV API 0.22](https://developer.amd.com/wp-content/resources/55766.PDF) Chapter 3), a guest owner can prevent any migration. 
While this effectively prevents our attack, this also prohibits migration in case of host failures.

## Usage

### Pre-requisites
1. A working SEV Setup. See [here](https://github.com/AMDESE/AMDSEV) for the required steps to enable SEV. SEV migration requires features which are not yet pushed upstream. The branches/repos used for this proof-of-concept are:
  * Linux kernel: https://github.com/codomania/kvm/ branch: `sev-migration-v3`
  * QEMU: https://github.com/codomania/qemu branch: `sev-migration-v3`
  * sev-tool: https://github.com/RobertBuhren/sev-tool branch: `master`

2. A Guest that allows migration. The `launch-qemu.sh` script sets the correct policy bits that allow migration to an SEV capable system.

3. The QEMU instance must accept connections via the `qmp` interface. The `launch-qemu.sh` script enables QMP on port `4444`.

4. An extracted CEK private key. NOTE: This key is not included in this repository. However, this repository contains the exported memory of an SEV protected virtual machine (`vm.mem`). Together with the PDH private key used for the migration (`pdh_priv.pem`), the memory can be decrypted using the `decrypt.py` script.

### Scripts

The `migrate.py` script is responsible for creating a certificate chain which is used by the target host to derive a shared secret that is used to protect the transport keys (`TIK` and `TEK`). 

The `migrate.py` script needs to be configured before the first use. Specifically the following parameters must be provided in the beginning of the script file:

* The target host: IP and QMP port.
* CEK_ID (optional) the ID corresponding to the extracted CEK. This is used to retrieve the signed CEK from the AMD keyserver.
* HOSTFILE: The filename where the virtual memory should be exported to. The script will eventually issue the qemu command `migrate: exec > HOSTFILE`.
 The filename is relative to the current working directory of the target QEMU process.

The script further requires an extracted CEK in the PEM format as the first argument. Optionally the signed ASK and ARK can be provided.

Example usage:

```
./migrate.py cek.pem cek_signed.cert ask_ark_naples.cert
```
or, to retrieve the certs from the AMD keyserver:

```
./migrate.py cek.pem
```

The script initiates the migration process and then exits. NOTE: migration with SEV is quite slow (~800 Kb/s).  The script will exit after migration is initiated. To monitor the status of the migration on the host, the *qemu-monitor* should be used.

The `decrypt.py` script performs the actual decryption of the exported guest memory. 
Before the first run, the location of the `sev-tool` binary needs to be specified in the script file.

To decrypt the exported guest memory the script requires the private pdh that was used to initiate the migration and the public key of the target host.
The `migrate.py` script saves the remote public PDH to `./pdh_remote.cert` and the local private PDH to `./pdh_priv.pem`.

To finally decrypt exported guest memory use:
```
./decrypt.py pdh_priv.pem pdh_remote.cert vm.mem
```
Where `vm.mem` is the encrypted virtual machine memory content.
The decrypted memory content will be saved in `./out`.

### POC Attack

The target guest used for this attack contains a secret in the form of the string `InsecureUntilProvenUpdated` that was entered using an encrypted SSH console.
While the string can be easily found inside the decrypted image, it is not present in the encrypted memory image.
