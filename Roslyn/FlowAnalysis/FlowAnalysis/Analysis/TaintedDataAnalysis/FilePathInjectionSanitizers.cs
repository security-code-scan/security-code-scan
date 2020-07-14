// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.PooledObjects;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class FilePathInjectionSanitizers
    {
        /// <summary>
        /// <see cref="SanitizerInfo"/>s for path traversal injection sanitizers.
        /// </summary>
        public static ImmutableHashSet<SanitizerInfo> SanitizerInfos { get; }

        static FilePathInjectionSanitizers()
        {
            var builder = PooledHashSet<SanitizerInfo>.GetInstance();

            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpServerUtility,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "MapPath",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpRequest,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "MapPath",
                });

            SanitizerInfos = builder.ToImmutableAndFree();
        }
    }
}
