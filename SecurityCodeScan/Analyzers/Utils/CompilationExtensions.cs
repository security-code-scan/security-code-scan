#nullable disable
using System;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal static class CompilationExtensions
    {
        /// <summary>
        /// Determine whether a type (given by name) is actually declared in the expected assembly (also given by name)
        /// </summary>
        /// <remarks>
        /// This can be used to decide whether we are referencing the expected framework for a given type. 
        /// For example, System.String exists in mscorlib for .NET Framework and System.Runtime for other framework (e.g. .NET Core). 
        /// </remarks>
        private static bool? IsTypeDeclaredInExpectedAssembly(Compilation compilation, string typeName, string assemblyName)
        {
            INamedTypeSymbol typeSymbol = compilation.GetTypeByMetadataName(typeName);
            return typeSymbol?.ContainingAssembly.Identity.Name.Equals(assemblyName, StringComparison.Ordinal);
        }

        /// <summary>
        /// Gets the version of the target .NET framework of the compilation.
        /// </summary>
        /// <returns>
        /// Version is Null if the target framework is not .NET Framework.
        /// </returns>
        /// <remarks>
        /// This method returns the assembly version of mscorlib for .NET Framework prior version 4.0. 
        /// It is using API diff tool to compare new classes in different versions and decide which version it is referencing
        /// i.e. for .NET framework 3.5, the returned version would be 2.0.0.0.
        /// For .NET Framework 4.X, this method returns the actual framework version instead of assembly version of mscorlib,
        /// i.e. for .NET framework 4.5.2, this method return 4.5.2 instead of 4.0.0.0.
        /// </remarks>
        public static (bool dotnetCore, Version version) GetDotNetFrameworkVersion(this Compilation compilation)
        {
            if (IsTypeDeclaredInExpectedAssembly(compilation, "System.String", "System.Runtime").GetValueOrDefault())
                return (true, null); // ideally would get .NET Core version, but not implemented since not needed yet

            if (!IsTypeDeclaredInExpectedAssembly(compilation, "System.String", "mscorlib").GetValueOrDefault())
            {
                return (false, null);
            }

            IAssemblySymbol mscorlibAssembly = compilation.GetTypeByMetadataName("System.String").ContainingAssembly;
            if (mscorlibAssembly.Identity.Version.Major < 4)
            {
                return (false, mscorlibAssembly.Identity.Version);
            }

            if (mscorlibAssembly.GetTypeByMetadataName("System.Diagnostics.Tracing.EventSourceCreatedEventArgs") != null)
            {
                return (false, new Version(4, 6, 2));
            }

            if (!IsTypeDeclaredInExpectedAssembly(compilation, "System.Net.TransportContext", "System").GetValueOrDefault())
            {
                return (false, null);
            }
            IAssemblySymbol systemAssembly = compilation.GetTypeByMetadataName("System.Net.TransportContext").ContainingAssembly;
            INamedTypeSymbol typeSymbol = systemAssembly.GetTypeByMetadataName("System.Net.TransportContext");
            if (!typeSymbol.GetMembers("GetTlsTokenBindings").IsEmpty)
            {
                return (false, new Version(4, 6, 1));
            }

            if (mscorlibAssembly.GetTypeByMetadataName("System.AppContext") != null)
            {
                return (false, new Version(4, 6));
            }
            typeSymbol = mscorlibAssembly.GetTypeByMetadataName("System.IO.UnmanagedMemoryStream");
            if (!typeSymbol.GetMembers("FlushAsync").IsEmpty)
            {
                return (false, new Version(4, 5, 2));
            }
            typeSymbol = mscorlibAssembly.GetTypeByMetadataName("System.Diagnostics.Tracing.EventSource");
            if (typeSymbol != null)
            {
                return (false, typeSymbol.GetMembers("CurrentThreadActivityId").IsEmpty ? new Version(4, 5) : new Version(4, 5, 1));
            }
            return (false, new Version(4, 0));
        }
    }
}
