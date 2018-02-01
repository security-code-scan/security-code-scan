using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WebConfigAnalyzer : DiagnosticAnalyzer, IExternalFileAnalyzer
    {
        public static readonly DiagnosticDescriptor RuleValidateRequest         = LocaleUtil.GetDescriptor("SCS0021");
        public static readonly DiagnosticDescriptor RuleEnableEventValidation   = LocaleUtil.GetDescriptor("SCS0022");
        public static readonly DiagnosticDescriptor RuleViewStateEncryptionMode = LocaleUtil.GetDescriptor("SCS0023");
        public static readonly DiagnosticDescriptor RuleEnableViewStateMac      = LocaleUtil.GetDescriptor("SCS0024");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
            RuleValidateRequest, RuleEnableEventValidation, RuleViewStateEncryptionMode, RuleEnableViewStateMac);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationAction(Compilation);
        }

        private void Compilation(CompilationAnalysisContext ctx)
        {
            //Load Web.config files : ASP.net web application configuration
            foreach (AdditionalText file in ctx.Options
                                               .AdditionalFiles
                                               .Where(file => Path.GetFileName(file.Path).StartsWith("Web.config")))
            {
                AnalyzeFile(file, ctx);
            }
        }

        private string CheckAttribute(XElement                   element,
                                      string                     attributeName,
                                      string                     defaultValue,
                                      Func<string, bool>         isGoodValue,
                                      DiagnosticDescriptor       diagnosticDescriptor,
                                      AdditionalText             file,
                                      CompilationAnalysisContext context)
        {
            var attributeValue = element?.Attribute(attributeName);
            var value = attributeValue?.Value ?? defaultValue;

            var v = value.Trim();
            if (isGoodValue(v))
                return v;

            var lineInfo   = (IXmlLineInfo)element;
            int lineNumber = element != null && lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;
            context.ReportDiagnostic(ExternalDiagnostic.Create(diagnosticDescriptor,
                                                               file.Path,
                                                               lineNumber,
                                                               element != null ? element.ToStringStartElement() : String.Empty));

            return v;
        }

        private void CheckMainConfigAndLocations(string                     attribute,
                                                 string                     defaultValue,
                                                 Func<string, bool>         isGoodValue,
                                                 DiagnosticDescriptor       diagnosticDescriptor,
                                                 XElement                   systemWeb,
                                                 string                     subElement,
                                                 XDocument                  doc,
                                                 AdditionalText             file,
                                                 CompilationAnalysisContext context)
        {
            var value = CheckAttribute(systemWeb?.Element(subElement),
                                       attribute,
                                       defaultValue,
                                       isGoodValue,
                                       diagnosticDescriptor,
                                       file,
                                       context);

            var locations = doc.Element("configuration")?.Elements("location");
            if (locations != null)
            {
                foreach (var location in locations)
                {
                    var pages = location.Element("system.web")?.Element(subElement);
                    CheckAttribute(pages,
                                   attribute,
                                   value,
                                   isGoodValue,
                                   diagnosticDescriptor,
                                   file,
                                   context);
                }
            }
        }

        public void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context)
        {
            var doc = XDocument.Load(file.Path, LoadOptions.SetLineInfo);
            var systemWeb = doc.Element("configuration")?.Element("system.web");

            CheckMainConfigAndLocations("validateRequest",
                                        "True",
                                        v => 0 == String.Compare("true", v, StringComparison.OrdinalIgnoreCase),
                                        RuleValidateRequest,
                                        systemWeb,
                                        "pages",
                                        doc,
                                        file,
                                        context);

            CheckMainConfigAndLocations("requestValidationMode",
                                        "4.0",
                                        v =>
                                        {
                                            if (!decimal.TryParse(v, out var version))
                                                return true;

                                            return version >= 4.0M;
                                        },
                                        RuleValidateRequest,
                                        systemWeb,
                                        "httpRuntime",
                                        doc,
                                        file,
                                        context);

            CheckMainConfigAndLocations("enableEventValidation",
                                        "True",
                                        v => 0 == String.Compare("true", v, StringComparison.OrdinalIgnoreCase),
                                        RuleEnableEventValidation,
                                        systemWeb,
                                        "pages",
                                        doc,
                                        file,
                                        context);

            CheckMainConfigAndLocations("viewStateEncryptionMode",
                                        "Auto",
                                        v => 0 == String.Compare("Always", v, StringComparison.OrdinalIgnoreCase),
                                        RuleViewStateEncryptionMode,
                                        systemWeb,
                                        "pages",
                                        doc,
                                        file,
                                        context);

            // https://blogs.msdn.microsoft.com/webdev/2014/09/09/farewell-enableviewstatemac/
            CheckMainConfigAndLocations("enableViewStateMac",
                                        "True",
                                        v => 0 == String.Compare("true", v, StringComparison.OrdinalIgnoreCase),
                                        RuleEnableViewStateMac,
                                        systemWeb,
                                        "pages",
                                        doc,
                                        file,
                                        context);
        }
    }
}
