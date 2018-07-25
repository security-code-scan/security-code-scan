using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    internal class VbCodeEvaluation
    {
        public static List<TaintAnalyzerExtensionVisualBasic> Extensions { get; set; } = new List<TaintAnalyzerExtensionVisualBasic>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            try
            {
                var state = new ExecutionState(ctx);

                foreach (var ext in Extensions)
                {
                    ext.VisitBegin(ctx.Node, state);
                }

                VisitNode(ctx.Node, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitEnd(ctx.Node, state);
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer fails silently.
                string errorMsg = $"Unhandled exception while visiting method {ctx.Node} : {e.Message}";
                Logger.Log(errorMsg);
                Logger.Log(e.StackTrace, false);
                throw new Exception(errorMsg, e);
            }
        }

        private VariableState VisitBlock(MethodBlockBaseSyntax node, ExecutionState state)
        {
            var lastState = new VariableState(node, VariableTaint.Unknown);

            foreach (StatementSyntax statement in node.Statements)
            {
                var statementState = VisitNode(statement, state);
                lastState          = statementState;

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state);
                }
            }

            return lastState;
        }

        /// <summary>
        /// Entry point that visits the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodBlockBaseSyntax node, ParameterListSyntax parameterList, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in parameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }

            return VisitBlock(node, state);
        }

        private VariableState VisitForEach(ForEachStatementSyntax node, ExecutionState state)
        {
            var variableState = VisitExpression(node.Expression, state);

            switch (node.ControlVariable)
            {
                case VariableDeclaratorSyntax variableDeclarator:
                    var names = variableDeclarator.Names;
                    foreach (var name in names)
                    {
                        state.AddNewValue(ResolveIdentifier(name.Identifier), variableState);
                    }

                    break;
                case IdentifierNameSyntax identifierName:
                    state.AddNewValue(ResolveIdentifier(identifierName.Identifier), variableState);
                    break;
                default:
                    throw new ArgumentException(nameof(node.ControlVariable));
            }

            return VisitNode(node.Expression, state);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //Logger.Log(node.GetType().ToString());

            switch (node)
            {
                case LocalDeclarationStatementSyntax localDeclaration:
                    return VisitLocalDeclaration(localDeclaration, state);
                case VariableDeclaratorSyntax variableDeclaration:
                    return VisitVariableDeclaration(variableDeclaration, state);
                case AssignmentStatementSyntax assignment:
                    return VisitAssignmentStatement(assignment, state);
                case ExpressionStatementSyntax expressionStatement:
                    return VisitExpressionStatement(expressionStatement, state);
                case ExpressionSyntax expression:
                    return VisitExpression(expression, state);
                case MethodBlockSyntax methodBlock:
                    return VisitMethodDeclaration(methodBlock, methodBlock.SubOrFunctionStatement.ParameterList, state);
                case ConstructorBlockSyntax constructorBlockSyntax:
                    return VisitMethodDeclaration(constructorBlockSyntax, constructorBlockSyntax.SubNewStatement.ParameterList, state);
                case PropertyBlockSyntax propertyBlockSyntax:
                {
                    foreach (var accessor in propertyBlockSyntax.Accessors)
                    {
                        VisitBlock(accessor, state);
                    }

                    return new VariableState(node, VariableTaint.Unknown);
                }
                case ReturnStatementSyntax returnStatementSyntax:
                    if (returnStatementSyntax.Expression == null)
                        return new VariableState(node, VariableTaint.Unknown);

                    return VisitExpression(returnStatementSyntax.Expression, state);
                case ForEachStatementSyntax forEachSyntax:
                    return VisitForEach(forEachSyntax, state);
            }

            foreach (var n in node.ChildNodes())
            {
                VisitNode(n, state);
            }

            var isBlockStatement = node is IfStatementSyntax ||
                                   node is ForStatementSyntax;

            if (!isBlockStatement)
            {
                Logger.Log("Unsupported statement " + node.GetType() + " (" + node + ")");
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

                if (declaration.AsClause is AsNewClauseSyntax asNewClauseSyntax)
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
            // TODO: Review other expression types that are unique to VB. 
            // TODO: Write tests to cover all these.

            switch (expression)
            {
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    return VisitMethodInvocation(invocationExpressionSyntax, state);
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    return VisitObjectCreation(objectCreationExpressionSyntax, state);
                case LiteralExpressionSyntax literalExpressionSyntax:
                    return new VariableState(literalExpressionSyntax, VariableTaint.Constant, literalExpressionSyntax.Token.Value);
                case IdentifierNameSyntax identifierNameSyntax:
                    return VisitIdentifierName(identifierNameSyntax, state);
                case BinaryExpressionSyntax binaryExpressionSyntax:
                    return VisitBinaryExpression(binaryExpressionSyntax, state);
                case MemberAccessExpressionSyntax memberAccessExpressionSyntax:
                    return VisitMemberAccessExpression(memberAccessExpressionSyntax, state);
                case ArrayCreationExpressionSyntax arrayCreationExpressionSyntax:
                    return VisitArrayCreation(arrayCreationExpressionSyntax, arrayCreationExpressionSyntax.Initializer, state);
                case CollectionInitializerSyntax collectionInitializerSyntax:
                    return VisitArrayCreation(collectionInitializerSyntax, collectionInitializerSyntax, state);
                case TypeOfExpressionSyntax typeOfExpressionSyntax:
                    return new VariableState(typeOfExpressionSyntax, VariableTaint.Safe);
                case GetTypeExpressionSyntax getTypeExpressionSyntax:
                    return new VariableState(getTypeExpressionSyntax, VariableTaint.Safe);
                case TernaryConditionalExpressionSyntax ternaryConditionalExpressionSyntax:
                {
                    VisitExpression(ternaryConditionalExpressionSyntax.Condition, state);
                    var finalState = new VariableState(ternaryConditionalExpressionSyntax, VariableTaint.Safe);

                    var whenTrueState  = VisitExpression(ternaryConditionalExpressionSyntax.WhenTrue, state);
                    finalState.Merge(whenTrueState);
                    var whenFalseState = VisitExpression(ternaryConditionalExpressionSyntax.WhenFalse, state);
                    finalState.Merge(whenFalseState);

                    return finalState;
                }
                case QueryExpressionSyntax queryExpressionSyntax:
                    return new VariableState(queryExpressionSyntax, VariableTaint.Unknown);
                case DirectCastExpressionSyntax directCastExpressionSyntax:
                    return VisitExpression(directCastExpressionSyntax.Expression, state);
                case CTypeExpressionSyntax cTypeExpressionSyntax:
                    return VisitExpression(cTypeExpressionSyntax.Expression, state);
            }

            Logger.Log("Unsupported expression " + expression.GetType() + " (" + expression + ")");
            return new VariableState(expression, VariableTaint.Unknown);
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            VariableState memberVariableState = null;
            if (node.Expression is MemberAccessExpressionSyntax memberAccessExpression)
            {
                if (memberAccessExpression.Expression != null)
                {
                    memberVariableState = VisitExpression(memberAccessExpression.Expression, state);
                }
                else
                {
                    var with = memberAccessExpression.AncestorsAndSelf().OfType<WithBlockSyntax>().First();
                    memberVariableState = VisitExpression(with.WithStatement.Expression, state);
                }
            }

            return VisitInvocationAndCreation(node, node.ArgumentList, state, memberVariableState);
        }

        private string GetMethodName(ExpressionSyntax node)
        {
            string methodName;
            switch (node)
            {
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    methodName = $"{objectCreationExpressionSyntax.NewKeyword} {objectCreationExpressionSyntax.Type}";
                    break;
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    methodName = invocationExpressionSyntax.Expression.ToString();
                    break;
                default:
                    methodName = node.ToString();
                    break;
            }

            return methodName;
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
                                                         ExecutionState state,
                                                         VariableState initialVariableState = null)
        {
            var symbol = state.GetSymbol(node);
            if (symbol == null)
                return new VariableState(node, VariableTaint.Unknown);

            var behavior    = symbol.GetMethodBehavior(state.AnalysisContext.Options.AdditionalFiles);
            var returnState = initialVariableState != null && !symbol.IsStatic
                                  ? initialVariableState
                                  : new VariableState(node,
                                                      behavior?.TaintFromArguments?.Any() == true ? VariableTaint.Safe
                                                                                                  : VariableTaint.Unknown);

            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument      = argList.Arguments[i];
                var argumentState = VisitExpression(argument.GetExpression(), state);

                Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);

                if (behavior == null)
                    continue;

                //If the API is at risk
                if ((argumentState.Taint == VariableTaint.Tainted ||
                     argumentState.Taint == VariableTaint.Unknown) && //Tainted values
                    //If the current parameter can be injected.
                    Array.Exists(behavior.InjectablesArguments, element => element == i))
                {
                    var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                    var diagnostic = Diagnostic.Create(newRule, node.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                    state.AnalysisContext.ReportDiagnostic(diagnostic);
                }
                else if (argumentState.Taint == VariableTaint.Constant && //Hard coded value
                         //If the current parameter is a password
                         Array.Exists(behavior.PasswordArguments, element => element == i))
                {
                    var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword);
                    var diagnostic = Diagnostic.Create(newRule, node.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                    state.AnalysisContext.ReportDiagnostic(diagnostic);
                }
                else if (Array.Exists(behavior.TaintFromArguments, element => element == i))
                {
                    returnState.Merge(argumentState);
                }

                //TODO: taint all objects passed as arguments
            }

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            return returnState;
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
            var leftSymbol = state.GetSymbol(leftExpression);
            MethodBehavior behavior = null;
            if (leftSymbol != null)
                behavior = leftSymbol.GetMethodBehavior(state.AnalysisContext.Options.AdditionalFiles);

            var variableState = VisitExpression(rightExpression, state);

            variableState = MergeVariableState(leftExpression, variableState, state);

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitAssignment(node, state, behavior, leftSymbol, variableState);
            }

            if (leftSymbol != null)
            {
                var rightTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(rightExpression).Type;
                if (rightTypeSymbol == null)
                    return new VariableState(rightExpression, VariableTaint.Unknown);

                var leftTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(leftExpression).Type;
                if (!state.AnalysisContext.SemanticModel.Compilation.ClassifyConversion(rightTypeSymbol, leftTypeSymbol).Exists)
                    return new VariableState(rightExpression, VariableTaint.Unknown);
            }

            if (behavior != null                              && //Injection
                behavior.IsInjectableField                    &&
                variableState.Taint != VariableTaint.Constant && //Skip safe values
                variableState.Taint != VariableTaint.Safe)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection, "title_assignment");
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            if (behavior != null         && //Known Password API
                behavior.IsPasswordField &&
                variableState.Taint == VariableTaint.Constant) //Only constant
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword, "title_assignment");
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: taint the variable being assigned.

            return variableState;
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

            state.CurrentVariableScope = finalState;
            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is NamedFieldInitializerSyntax namedFieldInitializerSyntax)
                {
                    VisitNamedFieldInitializer(namedFieldInitializerSyntax, state);
                }
                else
                {
                    Logger.Log(child.GetText().ToString().Trim() + " -> " + finalState);
                }
            }
            state.CurrentVariableScope = null;

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
            left.Merge(VisitExpression(expression.Right, state));
            return left;
        }

        /// <summary>
        /// Identifier name include variable name.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            return ResolveVariableState(expression, state);
        }

        private VariableState VisitMemberAccessExpression(MemberAccessExpressionSyntax expression, ExecutionState state)
        {
            return ResolveVariableState(expression, state);
        }

        private VariableState ResolveVariableState(ExpressionSyntax expression, ExecutionState state)
        {
            var varState = GetVariableState(expression, state);
            if (varState != null)
                return varState;

            var symbol = state.GetSymbol(expression);
            switch (symbol)
            {
                case null:
                return new VariableState(expression, VariableTaint.Unknown);
                case IFieldSymbol field:
                if (field.IsConst)
                    return new VariableState(expression, VariableTaint.Constant);

                if (!field.IsReadOnly)
                    return new VariableState(expression, VariableTaint.Unknown);

                var contantFields = ConfigurationManager.Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles)
                                                        .ConstantFields;

                if (contantFields.Contains(field.GetTypeName()))
                {
                    return new VariableState(expression, VariableTaint.Constant);
                }

                return new VariableState(expression, VariableTaint.Unknown);
                case IPropertySymbol prop:
                if (prop.IsVirtual || prop.IsOverride || prop.IsAbstract)
                    return new VariableState(expression, VariableTaint.Unknown);

                // TODO: Use public API
                var syntaxNodeProperty = prop.GetMethod.GetType().GetTypeInfo().BaseType.GetTypeInfo().GetDeclaredProperty("Syntax");
                var syntaxNode = (VisualBasicSyntaxNode)syntaxNodeProperty?.GetValue(prop.GetMethod);
                switch (syntaxNode)
                {
                    case null:
                    return new VariableState(expression, VariableTaint.Unknown);
                    case AccessorBlockSyntax blockSyntax:
                    // Recursion prevention: set the value into the map if we'll get back resolving it while resolving it dependency
                    MergeVariableState(expression, new VariableState(expression, VariableTaint.Unknown), state);
                    return VisitBlock(blockSyntax, state);
                }

                return new VariableState(expression, VariableTaint.Unknown);
            }

            return new VariableState(expression, VariableTaint.Unknown);
        }


        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitArrayCreation(SyntaxNode node, CollectionInitializerSyntax arrayInit, ExecutionState state)
        {
            var finalState = new VariableState(node, VariableTaint.Safe);
            if (arrayInit == null)
                return finalState;

            foreach (var ex in arrayInit.Initializers)
            {
                var exprState = VisitExpression(ex, state);
                finalState.Merge(exprState);
            }

            return finalState;
        }

        private VariableState GetVariableState(ExpressionSyntax expression, ExecutionState state)
        {
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                VariableState result;
                if (!(expression is IdentifierNameSyntax identifierNameSyntax))
                {
                    if (expression is MeExpressionSyntax && state.VariableStates.TryGetValue("this", out result))
                        return result;

                    return null;
                }

                var identifier = ResolveIdentifier(identifierNameSyntax.Identifier);
                if (state.VariableStates.TryGetValue(identifier, out result))
                    return result;

                return null;
            }

            var variableState = GetVariableState(memberAccessExpressionSyntax.Expression, state);
            if (variableState == null)
                return null;

            var stateIdentifier = ResolveIdentifier(memberAccessExpressionSyntax.Name.Identifier);
            //make sure this identifier exists
            if (variableState.PropertyStates.TryGetValue(stateIdentifier, out var propertyState))
                return propertyState;

            return null;
        }

        private VariableState MergeVariableState(ExpressionSyntax expression, VariableState newVariableState, ExecutionState state)
        {
            var variableStateToMerge = newVariableState ?? new VariableState(expression, VariableTaint.Unset);
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                var identifier = "";
                if (expression is IdentifierNameSyntax identifierNameSyntax)
                    identifier = ResolveIdentifier(identifierNameSyntax.Identifier);
                else if (expression is MeExpressionSyntax)
                    identifier = "this";

                if (state.CurrentVariableScope != null)
                {
                    state.CurrentVariableScope.AddOrMergeProperty(identifier, variableStateToMerge);
                    return state.CurrentVariableScope.PropertyStates[identifier];
                }

                state.AddOrUpdateValue(identifier, variableStateToMerge);
                return state.VariableStates[identifier];
            }

            var variableState = MergeVariableState(memberAccessExpressionSyntax.Expression, null, state);

            var stateIdentifier = ResolveIdentifier(memberAccessExpressionSyntax.Name.Identifier);
            //make sure this identifier exists
            variableState.AddOrMergeProperty(stateIdentifier, variableStateToMerge);
            return variableState.PropertyStates[stateIdentifier];
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
