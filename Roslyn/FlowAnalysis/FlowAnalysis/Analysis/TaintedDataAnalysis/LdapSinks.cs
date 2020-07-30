// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.PooledObjects;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class LdapSinks
    {
        /// <summary>
        /// <see cref="SinkInfo"/>s for tainted data LDAP injection sinks.
        /// </summary>
        public static ImmutableHashSet<SinkInfo> PathSinkInfos { get; }

        public static ImmutableHashSet<SinkInfo> FilterSinkInfos { get; }

        static LdapSinks()
        {
            var builder = PooledHashSet<SinkInfo>.GetInstance();

            builder.AddSinkInfo(
                WellKnownTypeNames.SystemDirectoryServicesActiveDirectoryADSearcher,
                SinkKind.LdapFilter,
                isInterface: false,
                isAnyStringParameterInConstructorASink: true,
                sinkProperties: new[] {
                    "Filter",
                },
                sinkMethodParameters: null);
            builder.AddSinkInfo(
                WellKnownTypeNames.SystemDirectoryServicesDirectorySearcher,
                SinkKind.LdapFilter,
                isInterface: false,
                isAnyStringParameterInConstructorASink: true,
                sinkProperties: new[] {
                    "PropertiesToLoad",
                    "Filter"
                },
                sinkMethodParameters: new[] {
                    (".ctor", new[] { "propertiesToLoad" } ),
                });

            FilterSinkInfos = builder.ToImmutableAndFree();

            builder = PooledHashSet<SinkInfo>.GetInstance();

            builder.AddSinkInfo(
                WellKnownTypeNames.SystemDirectoryDirectoryEntry,
                SinkKind.LdapPath,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new[] {
                    "Path",
                },
                sinkMethodParameters: new[] {
                    (".ctor", new[] { "path", "adsObject" } ),
                });

            PathSinkInfos = builder.ToImmutableAndFree();
        }
    }
}
