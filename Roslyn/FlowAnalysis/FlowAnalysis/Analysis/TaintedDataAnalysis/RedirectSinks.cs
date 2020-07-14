// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.PooledObjects;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class RedirectSinks
    {
        /// <summary>
        /// <see cref="SinkInfo"/>s for tainted data Redirect injection sinks.
        /// </summary>
        public static ImmutableHashSet<SinkInfo> SinkInfos { get; }

        static RedirectSinks()
        {
            var builder = PooledHashSet<SinkInfo>.GetInstance();

            builder.AddSinkInfo(
                WellKnownTypeNames.SystemWebHttpResponse,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new[] { "RedirectLocation" },
                sinkMethodParameters: new[] {
                    ( "Redirect", new[] { "url" }),
                    ( "RedirectPermanent", new[] { "url" }),
                    ( "RedirectToRoute", new[] { "routeName" }),
                    ( "RedirectToRoutePermanent", new[] { "routeName" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.MicrosoftAspNetCoreHttpResponse,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "Redirect", new[] { "location" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.SystemWebHttpResponseBase,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new[] { "RedirectLocation" },
                sinkMethodParameters: new[] {
                    ( "Redirect", new[] { "url" }),
                    ( "RedirectPermanent", new[] { "url" }),
                    ( "RedirectToRoute", new[] { "routeName" }),
                    ( "RedirectToRoutePermanent", new[] { "routeName" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.MicrosoftAspNetCoreMvcRedirectResult,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new[] { "Url" },
                sinkMethodParameters: new[] {
                    ( ".ctor", new[] { "url" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.SystemWebMvcRedirectResult,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new[] { "Url" },
                sinkMethodParameters: new[] {
                    ( ".ctor", new[] { "url" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.SystemWebMvcController,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "Redirect", new[] { "url" }),
                    ( "RedirectPermanent", new[] { "url" }),
                });
            builder.AddSinkInfo(
                WellKnownTypeNames.MicrosoftAspNetCoreMvcControllerBase,
                SinkKind.Redirect,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "Redirect", new[] { "url" }),
                    ( "RedirectPermanent", new[] { "url" }),
                    ( "RedirectPreserveMethod", new[] { "url" }),
                    ( "RedirectPermanentPreserveMethod", new[] { "url" }),
                });

            SinkInfos = builder.ToImmutableAndFree();
        }
    }
}
