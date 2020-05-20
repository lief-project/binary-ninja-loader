# LIEF ELF Loader for Binary Ninja

Author: Romain Thomas - @rh0main

**Experimental** ELF loader based on LIEF to process section-less binaries in Binary Ninja

## Description

In the current version (``2.0.2162``) of Binary Ninja, the ELF parser relies its analysis on ELF's sections.
Whistle the section provides a finer granularity compared to segments, they are not used to execute
the binary.
Therefore, sections can be corrupted or removed to break ELF parsers. This plugin enables to **optionally** use LIEF to handle
such binaries.

<p align="center" >
<img width="90%" src="https://github.com/lief-project/binary-ninja-loader/blob/master/.github/default.png"/><br />
</p>


<p align="center" >
<img width="90%" src="https://github.com/lief-project/binary-ninja-loader/blob/master/.github/lief.png"/><br />
</p>


## References

* https://blog.quarkslab.com/have-fun-with-lief-and-executable-formats.html
* Issue: https://github.com/Vector35/binaryninja-api/issues/1686


