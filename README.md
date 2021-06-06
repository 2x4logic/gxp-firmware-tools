Grandstream GXP VoIP phone firmware tools
=========================================

This had been tested with GXP21xx and GXP1xxx firmware images.

## gxp_decode usage

Given a firmware image "gxp2140fw.bin":

```
gxp_decode gxp2140fw.bin
```

The tool will extract the constituent partitions, each as a separate file, into the current directory.  The tool output to stdout will look similar to this:

```
writing gxp2140recovery.bin (v1.0.11.32) chksum decb 2021-03-04 11:51
writing gxp2140core.bin (v1.0.11.33) chksum 38b8 2021-03-04 11:51
writing gxp2140base.bin (v1.0.11.33) chksum 5bda 2021-03-04 11:51
writing gxp2140prog.bin (v1.0.11.35) chksum f957 2021-03-04 11:51
writing gxp2140oem.bin (v0.0.0.0) chksum 5cdc 2021-03-04 11:51
writing gxp2140lcl.bin (v1.0.11.34) chksum c9a5 2021-03-04 11:51
```

Each of these files can then be analyzed; [binwalk](https://github.com/ReFirmLabs/binwalk) is suggested.

## gxp_remaster usage

Given a firmware image "gxp2140fw.bin", a user-provided "gxp2140recovery.bin" to replace the existing partition of that name, and a to-be-created replacement firmware image named "modified.bin":

```
gxp_remaster gxp2140fw.bin modified.bin gxp2140recovery.bin
```

The tool will write "modified.bin", and this should consist of "gxp2140fw.bin" but with "gxp2140recovery.bin" used as a replacement.

NOTE: the phone will not update a partition unless the provided firmware image has a changed version number.  To remedy this, the tool toggles the least significant bit of the least significant version number to create such a difference (presuming the phone's existing firmware is the same as the firmware image being fed into gxp_remaster).  See the code commented as "update file header to reflect new version" for more details should your usage be different.

NOTE: you could very easily brick your phone by updating the firmware, so don't do this unless you really know what you are doing.

