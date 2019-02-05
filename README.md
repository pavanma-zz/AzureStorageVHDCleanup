# AzureStorageVHDCleanup
Save Azure cost by cleaning up unused VHDs in your Azure storage 

## Details
Azure stores Azure Virtual Machine OS and data disks in Azure storage accounts.  When a VM is deleted from Azure portal, the underlying OS and data disks may not get deleted.  Such disks continue to consume Azure storage and accounts for cost for storing them. These disks are called Orphaned Disks. This tool helps identify and delete the Orphaned disks.  The following types of Azure storage can be scanned and  cleaned up.
1) Classic UnManaged Disks
2) ARM Managed Disks
3) ARM UnManaged Disks

## Usage
1. The tool can be run in report mode to review the disks identified for clean up
2. Review the report, flag disks to skip, and run the tool in report mode.

More details are in Readme.docx.
