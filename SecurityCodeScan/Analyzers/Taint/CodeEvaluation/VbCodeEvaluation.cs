using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    public class VbCodeEvaluation : BaseCodeEvaluation
    {
        public static List<TaintAnalyzerExtension> Extensions { get; set; } = new List<TaintAnalyzerExtension>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodBlockSyntax;
            try
            {
                if (node == null)
                    return;

                var state = new ExecutionState(ctx);

                foreach (var ext in Extensions)
                {
                    ext.VisitBeginMethodDeclaration(node, state);
                }

                VisitMethodDeclaration(node, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitEndMethodDeclaration(node, state);
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string errorMsg   = $"Unhandle exception while visiting method: {e.Message}";
                Logger.Log(errorMsg);
                throw new Exception(errorMsg, e);
            }
        }

        /// <summary>
        /// Entry point that visit the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodBlockSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.SubOrFunctionStatement.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }

            foreach (StatementSyntax statement in node.Statements)
            {
                VisitNode(statement, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state);
                }
            }

            //The state return is irrelevant because it is not use.
            return new VariableState(node, VariableTaint.Unknown);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //Logger.Log(node.GetType().ToString());

            //Variable allocation
            var localDeclaration = node as LocalDeclarationStatementSyntax;
            if (localDeclaration != null)
            {
                return VisitLocalDeclaration(localDeclaration, state);
            }

            var variableDeclaration = node as VariableDeclaratorSyntax;
            if (variableDeclaration != null)
            {
                return VisitVariableDeclaration(variableDeclaration, state);
            }

            var assignment = node as AssignmentStatementSyntax;
            if (assignment != null)
            {
                return VisitAssignmentStatement(assignment, state);
            }

            //Expression
            var expressionStatement = node as ExpressionStatementSyntax;
            if (expressionStatement != null)
            {
                return VisitExpressionStatement(expressionStatement, state);
            }

            var expression = node as ExpressionSyntax;
            if (expression != null)
            {
                return VisitExpression(expression, state);
            }

            var methodBlock = node as MethodBlockSyntax;
            if (methodBlock != null)
            {
                return VisitMethodDeclaration(methodBlock, state);
            }

            foreach (var n in node.ChildNodes())
            {
                VisitNode(n, state);
            }

            //var isBlockStatement = node is BlockSyntax ||
            //                       node is IfStatementSyntax ||
            //                       node is ForEachStatementSyntax ||
            //                       node is ForStatementSyntax;
            var isBlockStatement = node is IfStatementSyntax ||
                                   node is ForEachStatementSyntax ||
                                   node is ForStatementSyntax;

            if (!isBlockStatement)
            {
                Logger.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");
            }

            return new VariableState(node, VariableTaint.Unknown);
        }

        /// <summary>
        /// Unwrap
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            foreach (var i in declaration.Declarators)
            {
                return VisitVariableDeclaration(i, state);
            }

            return new VariableState(declaration, VariableTaint.Unknown);
        }

        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclaratorSyntax declaration, ExecutionState state)
        {
            var lastState = new VariableState(declaration, VariableTaint.Unknown);

            foreach (var variable in declaration.Names)
            {
                var identifier  = variable.Identifier;
                var initializer = declaration.Initializer;
                if (initializer != null)
                {
                    EqualsValueSyntax equalsClause = initializer;

                    VariableState varState = VisitExpression(equalsClause.Value, state);

                    //varState.SetType(lastState.type);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }

                var asNewClauseSyntax = declaration.AsClause as AsNewClauseSyntax;
                if (asNewClauseSyntax != null)
                {
                    VariableState varState  = VisitExpression(asNewClauseSyntax.NewExpression, state);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }
            }

            return lastState;
        }

        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            // TODO: Review other expresion types that are unique to VB. 
            // TODO: Write tests to cover all these. 

            //Invocation
            var invocationExpressionSyntax = expression as InvocationExpressionSyntax;
            if (invocationExpressionSyntax != null)
            {
                return VisitMethodInvocation(invocationExpressionSyntax, state);
            }

            var objectCreationExpressionSyntax = expression as ObjectCreationExpressionSyntax;
            if (objectCreationExpressionSyntax != null)
            {
                return VisitObjectCreation(objectCreationExpressionSyntax, state);
            }

            if (expression is LiteralExpressionSyntax)
            {
                return new VariableState(expression, VariableTaint.Constant);
            }

            var identifierNameSyntax = expression as IdentifierNameSyntax;
            if (identifierNameSyntax != null)
            {
                return VisitIdentifierName(identifierNameSyntax, state);
            }

            //Arithmetic : Addition
            var binaryExpressionSyntax = expression as BinaryExpressionSyntax;
            if (binaryExpressionSyntax != null)
            {
                return VisitBinaryExpression(binaryExpressionSyntax, state);
            }

            var memberAccessExpressionSyntax = expression as MemberAccessExpressionSyntax;
            if (memberAccessExpressionSyntax != null)
            {
                var leftExpression = memberAccessExpressionSyntax.Expression;
                return VisitExpression(leftExpression, state);
            }

            var arrayCreationExpressionSyntax = expression as ArrayCreationExpressionSyntax;
            if (arrayCreationExpressionSyntax != null)
            {
                return VisitArrayCreation(arrayCreationExpressionSyntax, state);
            }

            var typeOfExpressionSyntax = expression as TypeOfExpressionSyntax;
            if (typeOfExpressionSyntax != null)
            {
                return new VariableState(typeOfExpressionSyntax, VariableTaint.Safe);
            }

            var ternaryConditionalExpressionSyntax = expression as TernaryConditionalExpressionSyntax;
            if (ternaryConditionalExpressionSyntax != null)
            {
                VisitExpression(ternaryConditionalExpressionSyntax.Condition, state);
                var finalState = new VariableState(ternaryConditionalExpressionSyntax, VariableTaint.Safe);

                var whenTrueState  = VisitExpression(ternaryConditionalExpressionSyntax.WhenTrue, state);
                finalState         = finalState.Merge(whenTrueState);
                var whenFalseState = VisitExpression(ternaryConditionalExpressionSyntax.WhenFalse, state);
                finalState         = finalState.Merge(whenFalseState);

                return finalState;
            }

            var queryExpressionSyntax = expression as QueryExpressionSyntax;
            if (queryExpressionSyntax != null)
            {
                return new VariableState(queryExpressionSyntax, VariableTaint.Unknown);
            }

            Logger.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(expression, VariableTaint.Unknown);
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }

        /// <summary>
        /// Logic for each method invocation (including constructor)
        /// The argument list is required because <code>InvocationExpressionSyntax</code> and 
        /// <code>ObjectCreationExpressionSyntax</code> do not share a common interface.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="argList"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitInvocationAndCreation(ExpressionSyntax node,
                                                         ArgumentListSyntax argList,
                                                         ExecutionState state)
        {
            var            symbol   = state.GetSymbol(node);
            MethodBehavior behavior = BehaviorRepo.GetMethodBehavior(symbol);

            int i = 0;
            if (argList == null)
            {
                return new VariableState(node, VariableTaint.Unknown);
            }

            var returnState = new VariableState(node, VariableTaint.Safe);

            foreach (var argument in argList.Arguments)
            {
                var argumentState = VisitExpression(argument.GetExpression(), state);

                if (symbol != null)
                {
                    Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
                }

                if (behavior != null)
                {
                    //If the API is at risk
                    if ((argumentState.Taint == VariableTaint.Tainted ||
                         argumentState.Taint == VariableTaint.Unknown) &&   //Tainted values
                        //If the current parameter can be injected.
                        Array.Exists(behavior.InjectablesArguments, element => element == i))
                    {
                        var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (argumentState.Taint == VariableTaint.Constant &&                   //Hard coded value
                             //If the current parameter is a password
                             Array.Exists(behavior.PasswordArguments, element => element == i))
                    {
                        var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (Array.Exists(behavior.TaintFromArguments, element => element == i))
                    {
                        returnState = returnState.Merge(argumentState);
                    }
                }

                //TODO: tainted all object passed in argument

                i++;
            }

            //Additionnal analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            var hasTaintFromArguments = behavior?.TaintFromArguments?.Length > 0;
            return hasTaintFromArguments ? returnState : new VariableState(node, VariableTaint.Unknown);
        }

        private VariableState VisitAssignmentStatement(AssignmentStatementSyntax node, ExecutionState state)
        {
            return VisitAssignment(node, node.Left, node.Right, state);
        }

        private VariableState VisitNamedFieldInitializer(NamedFieldInitializerSyntax node, ExecutionState state)
        {
            return VisitAssignment(node, node.Name, node.Expression, state);
        }

        private VariableState VisitAssignment(VisualBasicSyntaxNode node,
                                              ExpressionSyntax      leftExpression,
                                              ExpressionSyntax      rightExpression,
                                              ExecutionState        state)
        {
            var            symbol   = state.GetSymbol(leftExpression);
            MethodBehavior behavior = BehaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(rightExpression, state);

            //Additionnal analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitAssignment(node, state, behavior, symbol, variableState);
            }

            IdentifierNameSyntax parentIdentifierSyntax = GetParentIdentifier(leftExpression);
            if (parentIdentifierSyntax != null)
            {
                state.MergeValue(ResolveIdentifier(parentIdentifierSyntax.Identifier), variableState);
            }

            if (behavior != null                              && //Injection
                behavior.IsInjectableField                    &&
                variableState.Taint != VariableTaint.Constant && //Skip safe values
                variableState.Taint != VariableTaint.Safe)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            if (behavior != null         && //Known Password API
                behavior.IsPasswordField &&
                variableState.Taint == VariableTaint.Constant) //Only constant
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: tainted the variable being assign.

            return variableState;
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

            foreach (SyntaxNode child in node.DescendantNodes())
            {
                var namedFieldInitializerSyntax = child as NamedFieldInitializerSyntax;
                if (namedFieldInitializerSyntax != null)
                {
                    finalState = finalState.Merge(VisitNamedFieldInitializer(namedFieldInitializerSyntax, state));
                }
                else
                {
                    Logger.Log(child.GetText().ToString().Trim() + " -> " + finalState);
                }
            }

            return finalState;
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(BinaryExpressionSyntax expression, ExecutionState state)
        {
            VariableState left  = VisitExpression(expression.Left,  state);
            VariableState right = VisitExpression(expression.Right, state);
            return left.Merge(right);
        }

        /// <summary>
        /// Identifier name include variable name.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            var value = ResolveIdentifier(expression.Identifier);
            return state.GetValueByIdentifier(value);
        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitArrayCreation(ArrayCreationExpressionSyntax node, ExecutionState state)
        {
            var arrayInit = node.Initializer;

            var finalState = new VariableState(node, VariableTaint.Safe);
            if (arrayInit == null)
                return finalState;

            foreach (var ex in arrayInit.Initializers)
            {
                var exprState = VisitExpression(ex, state);
                finalState    = finalState.Merge(exprState);
            }

            return finalState;
        }

        /// <summary>
        /// Return the top member from an assignment.
        /// <code>
        /// a.b.c = 1234; //Will return a
        /// d.e = 1234 //Will return d
        /// </code>
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        private IdentifierNameSyntax GetParentIdentifier(ExpressionSyntax expression)
        {
            while (true)
            {
                var memberAccessExpressionSyntax = expression as MemberAccessExpressionSyntax;
                if (memberAccessExpressionSyntax == null)
                    break;

                expression = memberAccessExpressionSyntax.Expression;
            }

            var identifierNameSyntax = expression as IdentifierNameSyntax;
            return identifierNameSyntax;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="syntaxToken"></param>
        /// <returns></returns>
        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }
    }
}
