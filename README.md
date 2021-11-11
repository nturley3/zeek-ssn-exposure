NOTE: This repository was duplicated from https://github.com/sethhall/ssn-exposure. This was required to
reconfigure module for support on Corelight appliances. This was based on a technical discussion
with Seth Hall since at the time of this note, the Corelight 1.15 appliances do not support redefinitions
outside of a modules scope (e.g. local.bro). This module has been modified to support these redefs within  
the module scope via a script loaded at module instantiation. This allows modules such as ssn-exposure to
function correctly on Corelight.

SSN Exposure
============

Detect US Social Security Numbers with Bro.  This script only works with Bro 2.4+.

Installation
------------

Bro Package Manager
*******************

This is a test for the new Bro package manager.  If you don't have the package
manager and you don't want to work with early code please use the alternate 
manual installation method.

::

	bro-pkg refresh
	bro-pkg install ssn-exposure

Alternate Manual Installation
*****************************

::

	cd <prefix>/share/bro/site/
	git clone git://github.com/sethhall/ssn-exposure.git
	echo "@load ssn-exposure" >> local.bro

After the ssn-exposure module is loaded, follow the configuration examples below.  One or both of the following options must be done or the script won't do anything.

Configuration
-------------

There are some configuration options that you will likely want to pay attention to.  In particular, it's likely that you will want to configure the SsnExposure::prefixes variable unless you have a list of relevant SSNs for your organization in which case you will want to configure the SsnExposure::ssn_file variable to point to a file on disk with a list of SSNs that are relevant for you.

Examples
--------

Prefix configuration
~~~~~~~~~~~~~~~~~~~~

This method is more prone to false positives than the next method, but it's quick and easy to begin using after finding the relevant state prefixes from: http://www.mrfa.org/ssn.htm

Configure likely state prefixes in local.bro::

	redef SsnExposure::prefixes += {
		[$state="Ohio",         $low=268, $high=302],
		[$state="Pennsylvania", $low=159, $high=211],
	};

SSN list configuration
~~~~~~~~~~~~~~~~~~~~~~

A list of "known SSNs" which will be used for validation after candidate values are extracted from the network.

Configure the SSN list file in local.bro::

	redef SsnExposure::ssn_file = "/var/data/ssn-list.txt";

Create the ssn-list.txt (or whatever file you referenced above)::

	123456789
	123456788
	123456777
	123456666

This file will be reread everytime it changes at runtime so updates do not require a restart.
