// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.PooledObjects;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class LdapSanitizers
    {
        /// <summary>
        /// <see cref="SanitizerInfo"/>s for LDAP injection sanitizers.
        /// </summary>
        public static ImmutableHashSet<SanitizerInfo> PathSanitizerInfos { get; }

        public static ImmutableHashSet<SanitizerInfo> FilterSanitizerInfos { get; }

        static LdapSanitizers()
        {
            var builder = PooledHashSet<SanitizerInfo>.GetInstance();

            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "LdapDistinguishedNameEncode",
                });

            PathSanitizerInfos = builder.ToImmutableAndFree();

            builder = PooledHashSet<SanitizerInfo>.GetInstance();

            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "LdapEncode",
                    "LdapFilterEncode",
                });

            FilterSanitizerInfos = builder.ToImmutableAndFree();
        }
    }
}
