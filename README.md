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

