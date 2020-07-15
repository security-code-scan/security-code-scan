// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.PooledObjects;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class SqlSinks
    {
        /// <summary>
        /// <see cref="SinkInfo"/>s for tainted data SQL sinks.
        /// </summary>
        public static ImmutableHashSet<SinkInfo> SinkInfos { get; }

        static SqlSinks()
        {
            var sinkInfosBuilder = PooledHashSet<SinkInfo>.GetInstance();

            sinkInfosBuilder.AddSinkInfo(
                "Test",
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "Sink", new[] { "input", } ),
                    ( "Injectable", new[] { "dangerous", } ),
                    ( "InjectableOpt", new[] { "dangerous", } ),
                });
            sinkInfosBuilder.AddSinkInfo(
                "TestExtensions",
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "Injectable2", new[] { "dangerous", } ),
                    ( "InjectableOpt2", new[] { "dangerous", } ),
                });






            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemDataIDbCommand,
                SinkKind.Sql,
                isInterface: true,
                isAnyStringParameterInConstructorASink: true,
                sinkProperties: new string[] {
                    "CommandText",
                },
                sinkMethodParameters: null);

            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemDataIDataAdapter,
                SinkKind.Sql,
                isInterface: true,
                isAnyStringParameterInConstructorASink: true,
                sinkProperties: null,
                sinkMethodParameters: null);

            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemWebUIWebControlsSqlDataSource,
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new string[] {
                    "ConnectionString",
                    "DeleteCommand",
                    "InsertCommand",
                    "SelectCommand",
                    "UpdateCommand",
                },
                sinkMethodParameters: new[] {
                    ( ".ctor", new[] { "selectCommand", } ),
                });
            //sinkInfosBuilder.AddSinkInfo(
            //    WellKnownTypeNames.MicrosoftEntityFrameworkCoreRelationalDatabaseFacadeExtensions,
            //    SinkKind.Sql,
            //    isInterface: false,
            //    isAnyStringParameterInConstructorASink: false,
            //    sinkProperties: null,
            //    sinkMethodParameters: new[] {
            //        ( "ExecuteSqlCommand", new[] { "sql", } ),
            //        ( "ExecuteSqlCommandAsync", new[]{ "sql", } ),
            //        ( "ExecuteSqlRaw", new[] { "sql", } ),
            //        ( "ExecuteSqlRawAsync", new[] { "sql", } ),
            //    });
            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemDataEntityDatabase,
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "ExecuteSqlCommand", new[] { "sql", } ),
                    ( "ExecuteSqlCommandAsync", new[]{ "sql", } ),
                    ( "SqlQuery", new[] { "sql", } ),
                });
            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemDataEntityDbSet,
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "SqlQuery", new[] { "sql", } ),
                });
            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemDataEntityDbSetGenerics,
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "SqlQuery", new[] { "sql", } ),
                });
            //sinkInfosBuilder.AddSinkInfo(
            //    WellKnownTypeNames.SystemDataSqlClientSqlDataAdapter,
            //    SinkKind.Sql,
            //    isInterface: false,
            //    isAnyStringParameterInConstructorASink: false,
            //    sinkProperties: null,
            //    sinkMethodParameters: new[] {
            //        ( ".ctor", new[] { "selectCommandText", } ),
            //    });
            //sinkInfosBuilder.AddSinkInfo(
            //    WellKnownTypeNames.SystemDataSqlClientSqlCommand,
            //    SinkKind.Sql,
            //    isInterface: false,
            //    isAnyStringParameterInConstructorASink: false,
            //    sinkProperties: null,
            //    sinkMethodParameters: new[] {
            //        ( ".ctor", new[] { "cmdText", } ),
            //    });
            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.MicrosoftPracticesEnterpriseLibraryDataDatabase,
                SinkKind.Sql,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: null,
                sinkMethodParameters: new[] {
                    ( "GetSqlStringCommand", new[] { "query", } ),
                });

            SinkInfos = sinkInfosBuilder.ToImmutableAndFree();
        }
    }
}
