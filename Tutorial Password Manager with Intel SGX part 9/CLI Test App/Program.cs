// Copyright 2016 Intel Corporation.

// The source code, information and material ("Material") contained herein is
// owned by Intel Corporation or its suppliers or licensors, and title to such
// Material remains with Intel Corporation or its suppliers or licensors. The
// Material contains proprietary information of Intel or its suppliers and
// licensors. The Material is protected by worldwide copyright laws and treaty
// provisions. No part of the Material may be used, copied, reproduced, modified,
// published, uploaded, posted, transmitted, distributed or disclosed in any way
// without Intel's prior express written permission. No license under any patent,
// copyright or other intellectual property rights in the Material is granted to
// or conferred upon you, either expressly, by implication, inducement, estoppel
// or otherwise. Any license under such intellectual property rights must be
// express and approved by Intel in writing.

// Include any supplier copyright notices as supplier requires Intel to use.

// Include supplier trademarks or logos as supplier requires Intel to use,
// preceded by an asterisk. An asterisked footnote can be added as follows:
// *Third Party trademarks are the property of their respective owners.

// Unless otherwise agreed by Intel in writing, you may not remove or alter this
// notice or any other notice embedded in Materials by Intel or Intel's suppliers
// or licensors in any way.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.IO;
using PasswordManagerTest;

namespace CLI_Test_App
{
    class Program
    {
        static void Main(string[] args)
        {
            TestSetup setup = new TestSetup();
            FeatureSupport sgxfeature = new FeatureSupport();
            TestSuite tests;

            setup.setSGXSupport(sgxfeature.is_enabled() == 1);

            tests= new TestSuite(setup);
            Exit(tests.RunAll() ? 0 : 1);
        }

        static void Exit(int code)
        {
            Console.Write("Hit ENTER to exit...");
            Console.ReadLine();
            Environment.Exit(code);
        }

    }
}
