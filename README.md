[![Build Status](https://travis-ci.com/IBM/watsonxdata-python-sdk.svg?&branch=main)](https://travis.ibm.com/IBM/watsonxdata-python-sdk)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
# IBM Cloud Watsonx.data Python SDK 0.4.0

Python client library to interact with various [IBM Cloud Watsonx-data APIs](https://cloud.ibm.com/apidocs?category=watsonxdata).

Disclaimer: this SDK is being released initially as a **pre-release** version.
Changes might occur which impact applications that use this SDK.

## Table of Contents

<!--
  The TOC below is generated using the `markdown-toc` node package.

      https://github.com/jonschlinkert/markdown-toc

  You should regenerate the TOC after making changes to this file.

      npx markdown-toc -i README.md
  -->

<!-- toc -->

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Using the SDK](#using-the-sdk)
- [Questions](#questions)
- [Issues](#issues)
- [Open source @ IBM](#open-source--ibm)
- [Contributing](#contributing)
- [License](#license)

<!-- tocstop -->

## Overview

The IBM Cloud Watsonx-data Python SDK allows developers to programmatically interact with the following
IBM Cloud services:

Service Name | Module Name | Imported Class Name
--- | --- | ---
[Watsonx.data](https://cloud.ibm.com/apidocs/watsonxdata) | watsonx_data_v2| ibm_watsonxdata

## Prerequisites

[ibm-cloud-onboarding]: https://cloud.ibm.com/registration

* An [IBM Cloud][ibm-cloud-onboarding] account.
* An IAM API key to allow the SDK to access your account. Create one [here](https://cloud.ibm.com/iam/apikeys).
* Python 3.7 or above.

## Installation

To install, use `pip`:

```bash
pip install --upgrade ibm-watsonxdata
```

Then in your code, you can import the appropriate service like this:
```
from ibm-watsonxdata.<service-module-name> import *
```
where `<service-module-name>` is the service's module name from the table above

## Using the SDK
For general SDK usage information, please see [this link](https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md)

## Questions

If you are having difficulties using this SDK or have a question about the IBM Cloud services,
please ask a question at
[Stack Overflow](http://stackoverflow.com/questions/ask?tags=ibm-cloud).

## Issues
If you encounter an issue with the project, you are welcome to submit a
[bug report](https://github.com/IBM/watsonxdata-python-sdk/issues).
Before that, please search for similar issues. It's possible that someone has already reported the problem.

## Open source @ IBM
Find more open source projects on the [IBM Github Page](http://ibm.github.io/)

## Contributing
See [CONTRIBUTING.md](https://github.com/IBM/watsonxdata-python-sdk/blob/main/CONTRIBUTING.md).

## License

This SDK is released under the Apache 2.0 license.
The license's full text can be found in [LICENSE](https://github.com/IBM/watsonxdata-python-sdk/blob/main/LICENSE).
