# memprocsimulator
A single a header file you can include instead of vmmdll.h to test stuff, without the need of a slow fpga card.
Credits to Ulf Frisk for this amazing library.

There are only a few methods implemented:
* VMMDLL_Initialize
* VMMDLL_Close
* VMMDLL_Scatter_Initialize
* VMMDLL_Scatter_CloseHandle
* VMMDLL_PidGetFromName
* VMMDLL_ProcessGetModuleBaseU
* VMMDLL_MemReadEx
* VMMDLL_MemWrite
* VMMDLL_Scatter_PrepareEx
* VMMDLL_Scatter_Prepare
* VMMDLL_Scatter_ExecuteRead
* VMMDLL_Scatter_Execute
* VMMDLL_Scatter_Clear

If something is missing, feel free to create an issue or a pull request. Thank you.

Here a link to the original memprocfs: https://github.com/ufrisk/MemProcFS/
