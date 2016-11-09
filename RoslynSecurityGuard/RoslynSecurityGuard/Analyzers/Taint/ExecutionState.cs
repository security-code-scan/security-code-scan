using System.Collections.Generic;

using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis;
using System;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    /// <summary>
    /// Execution state at a given statement. It will be alter after each statement are evaluated.
    /// </summary>
    public class ExecutionState
    {
        public SyntaxNodeAnalysisContext AnalysisContext { get; }
        public IDictionary<string, VariableState> Variables { get; private set; }

        public ExecutionState(SyntaxNodeAnalysisContext ctx)
        {
            AnalysisContext = ctx;
            Variables = new Dictionary<string, VariableState>();
        }

        public void AddNewValue(string identifier, VariableState value) {
            if (Variables.ContainsKey(identifier)) //Override existing value
            {
                Variables.Remove(identifier);
            }
            Variables.Add(identifier, value);
        }

        public VariableState GetValueByIdentifier(string identifier) {
            VariableState value = new VariableState(VariableTaint.UNKNOWN);
            Variables.TryGetValue(identifier, out value);
            return value;
        }

        /// <summary>
        /// Resolve semantic class name of a given variable reference.
        /// </summary>
        /// <param name="node">Expression to evaluate</param>
        /// <returns>The resolved symbol with the complete class name and method name.</returns>
        public ISymbol GetSymbol(ExpressionSyntax node) {
            return AnalysisContext.SemanticModel.GetSymbolInfo(node).Symbol;
        }

        public void AddTag(string variableAccess, VariableTag httpCookieSecure)
        {
            try
            {
                Variables[variableAccess].AddTag(httpCookieSecure);
            }
            catch (KeyNotFoundException e) {
            }
        }
    }
}
