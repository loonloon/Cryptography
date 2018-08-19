View the Intel(r) SGX Tutorial Series at:

https://software.intel.com/en-us/articles/introducing-the-intel-software-guard-extensions-tutorial-series

This source code is associated with Part 5, Enclave Development.

To build, open "Intel SGX Tutorial Series Part 5.sln" in Visual Studio 2013.
This should open four projects:

  * CLI Test App
  * Enclave
  * EnclaveBridge
  * PasswordManagerCore

The CLI Test App source will probably show a bunch of errors at first since 
it depends on a DLL that hasn't been built yet. That's OK. Just build the 
project (it should build in the correct order) and run.

Before running, copy the reference vault file "reference.vlt" from the 
"sample vault" folder to your Documents folder (if you prefer a different 
location, change the path to the directory in TestSetup.cs. The test suite 
tries very hard to preserve the original copy of this file but sometimes 
terrible things happen, so make sure you keep a backup copy somewhere.

This release has been hardcoded to execute the SGX code path. If you do
not have an Intel SGX-capable system, you will need to build the solution
in Simulation mode.

The "doc" folder contains the spec for the vault file format as well as
the passwords and encryption keys for the sample vault.

--

This software is subject to the U.S. Export Administration Regulations and 
other U.S. law, and may not be exported or re-exported to certain countries 
(Cuba, Iran, North Korea, Sudan, Syria, and the Crimea region of Ukraine) 
or to persons or entities prohibited from receiving U.S. exports (including 
Denied Parties, Specially Designated Nationals, and entities on the Bureau 
of Export Administration Entity List or involved with missile technology or 
nuclear, chemical or biological weapons).

