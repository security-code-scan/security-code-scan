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
                string errorMsg = $"Unhandled exception while visiting method {ctx.Node}\n{e.Message}";
                Logger.Log(errorMsg);
                if (e.InnerException != null)
                    Logger.Log($"{e.InnerException.Message}");
                Logger.Log($"\n{e.StackTrace}", false);
                throw;
            }
        }

        private VariableState VisitBlock(MethodBlockBaseSyntax node, ExecutionState state)
        {
            var lastState = new VariableState(node, VariableTaint.Unknown);

            foreach (StatementSyntax statement in node.Statements)
            {
                var statementState = VisitNode(statement, state);
                lastState = statementState;

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state);
                }
            }

            return lastState;
        }

        private void TaintParameters(MethodBlockBaseSyntax node, ParameterListSyntax parameterList, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in parameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }
        }

        /// <summary>
        /// Entry point that visits the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodBlockBaseSyntax node, ParameterListSyntax parameterList, ExecutionState state)
        {
            var config = ConfigurationManager.Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles);
            if (config.AuditMode)
            {
                TaintParameters(node, parameterList, state);
            }
            else
            {
                var symbol = state.AnalysisContext.SemanticModel.GetDeclaredSymbol(node);
                if (symbol != null)
                {
                    if (symbol.IsTaintEntryPoint(config.TaintEntryPoints))
                        TaintParameters(node, parameterList, state);
                }
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
            switch (node)
            {
                case UnaryExpressionSyntax unaryExpressionSyntax:
                    return VisitNode(unaryExpressionSyntax.Operand, state);
                case LocalDeclarationStatementSyntax localDeclaration:
                    return VisitLocalDeclaration(localDeclaration, state);
                case VariableDeclaratorSyntax variableDeclaration:
                    return VisitVariableDeclaration(variableDeclaration, state);
                case AssignmentStatementSyntax assignment:
                    if (assignment.Kind() != SyntaxKind.SimpleAssignmentStatement)
                    {
                        var left            = VisitExpression(assignment.Left, state);
                        var assignmentState = VisitAssignment(assignment, assignment.Left, assignment.Right, state);
                        left.MergeTaint(assignmentState.Taint);
                        return left;
                    }
                    else
                    {
                        var assignmentState = VisitAssignment(assignment, assignment.Left, assignment.Right, state);
                        return MergeVariableState(assignment.Left, assignmentState, state);
                    }
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
                                   node is ElseBlockSyntax ||
                                   node is ForStatementSyntax ||
                                   node is UsingStatementSyntax;

            if (!isBlockStatement)
            {
#if DEBUG
                //throw new Exception("Unsupported statement " + node.GetType() + " (" + node + ")");
                Logger.Log("Unsupported statement " + node.GetType() + " (" + node + ")");
#endif
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
            var finalState = new VariableState(declaration, VariableTaint.Unset);

            foreach (var i in declaration.Declarators)
            {
                finalState.MergeTaint(VisitVariableDeclaration(i, state).Taint);
            }

            return finalState;
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
                    VariableState varState = VisitExpression(asNewClauseSyntax.NewExpression, state);
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

                    var whenTrueState = VisitExpression(ternaryConditionalExpressionSyntax.WhenTrue, state);
                    finalState.MergeTaint(whenTrueState.Taint);
                    var whenFalseState = VisitExpression(ternaryConditionalExpressionSyntax.WhenFalse, state);
                    finalState.MergeTaint(whenFalseState.Taint);

                    return finalState;
                }
                case QueryExpressionSyntax queryExpressionSyntax:
                    return new VariableState(queryExpressionSyntax, VariableTaint.Unknown);
                case InterpolatedStringExpressionSyntax interpolatedStringExpressionSyntax:
                    return VisitInterpolatedString(interpolatedStringExpressionSyntax, state);
                case DirectCastExpressionSyntax directCastExpressionSyntax:
                    return VisitExpression(directCastExpressionSyntax.Expression, state);
                case CTypeExpressionSyntax cTypeExpressionSyntax:
                    return VisitExpression(cTypeExpressionSyntax.Expression, state);
            }

#if DEBUG
            Logger.Log("Unsupported expression " + expression.GetType() + " (" + expression + ")");
#endif
            return new VariableState(expression, VariableTaint.Unknown);
        }

        private VariableState VisitInterpolatedString(InterpolatedStringExpressionSyntax interpolatedString,
                                                      ExecutionState                     state)
        {
            var varState = new VariableState(interpolatedString, VariableTaint.Constant);

            foreach (var content in interpolatedString.Contents)
            {
                if (content is InterpolatedStringTextSyntax)
                {
                    varState.MergeTaint(VariableTaint.Constant);
                }

                if (!(content is InterpolationSyntax interpolation))
                    continue;

                var expressionState = VisitExpression(interpolation.Expression, state);
                varState.MergeTaint(expressionState.Taint);
            }

            return varState;
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

                var taintSourceState = CheckIfTaintSource(memberAccessExpression, state);
                if (taintSourceState != null)
                    memberVariableState.MergeTaint(taintSourceState.Taint);
            }

            return VisitInvocationAndCreation(node, node.ArgumentList, state, memberVariableState?.Taint, memberVariableState);
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

        private bool CheckPreconditions(MethodBehavior behavior, bool isExtensionMethod, ArgumentListSyntax argList, ExecutionState state)
        {
            if (behavior.PreConditions == null || !behavior.PreConditions.Any())
                return true;

            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument            = argList.Arguments[i];
                var adjustedArgumentIdx = isExtensionMethod ? i + 1 : i;

                if (!behavior.PreConditions.TryGetValue(adjustedArgumentIdx, out var preconditionArgumentValue))
                {
                    continue;
                }

                var calculatedArgumentValue = state.AnalysisContext.SemanticModel.GetConstantValue(argument.GetExpression());
                if (calculatedArgumentValue.HasValue && calculatedArgumentValue.Value.Equals(preconditionArgumentValue))
                {
                    continue;
                }

                return false;
            }

            return true;
        }

        /// <summary>
        /// Logic for each method invocation (including constructor)
        /// The argument list is required because <code>InvocationExpressionSyntax</code> and 
        /// <code>ObjectCreationExpressionSyntax</code> do not share a common interface.
        /// </summary>
        private VariableState VisitInvocationAndCreation(ExpressionSyntax   node,
                                                         ArgumentListSyntax argList,
                                                         ExecutionState     state,
                                                         VariableTaint?     initialTaint = null,
                                                         VariableState       memberVariableState = null)
        {
            var symbol = state.GetSymbol(node);
            if (symbol == null)
                return new VariableState(node, initialTaint ?? VariableTaint.Unknown);

            var  methodSymbol      = symbol as IMethodSymbol;
            bool isExtensionMethod = methodSymbol?.ReducedFrom != null;
            var  behavior          = symbol.GetMethodBehavior(state.CachedMethodBehaviors);
            bool applyCustomTaint  = behavior != null && CheckPreconditions(behavior, isExtensionMethod, argList, state);

            VariableState returnState = initialTaint != null && !symbol.IsStatic
                                            ? new VariableState(node, initialTaint.Value)
                                            : new VariableState(node, argList?.Arguments.Count > 0 && behavior != null
                                                                          ? VariableTaint.Unset
                                                                          : VariableTaint.Unknown);

            var config = ConfigurationManager.Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles);
            var argCount = argList?.Arguments.Count;
            var argumentStates = argCount.HasValue &&
                                 argCount.Value > 0 &&
                                 (behavior?.PostConditions.Any(c => c.Key != -1 && (c.Value.TaintFromArguments.Any(t => t != -1) || c.Value.Taint != 0ul)) == true ||
                                  methodSymbol != null && methodSymbol.Parameters.Any(x => x.RefKind != RefKind.None))
                                     ? new VariableState[argCount.Value]
                                     : null;

            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument      = argList.Arguments[i];
                var argumentState = VisitExpression(argument.GetExpression(), state);
                if (argumentStates != null)
                    argumentStates[i] = argumentState;

#if DEBUG
                Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
#endif

                if (behavior != null)
                {
                    var adjustedArgumentIdx = isExtensionMethod ? i + 1 : i;

                    if ((argumentState.Taint & (config.AuditMode ? VariableTaint.Tainted | VariableTaint.Unknown : VariableTaint.Tainted)) != 0)
                    {
                        //If the current parameter can be injected.
                        if (behavior.InjectableArguments.TryGetValue(adjustedArgumentIdx, out var requiredTaintBits) &&
                            (requiredTaintBits & (ulong)argumentState.Taint) != requiredTaintBits)
                        {
                            var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                            var diagnostic = Diagnostic.Create(newRule, argument.GetExpression().GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                            state.AnalysisContext.ReportDiagnostic(diagnostic);
                        }
                    }

                    if (argumentState.Taint == VariableTaint.Constant && //Hard coded value
                                                                         //If the current parameter is a password
                        behavior.PasswordArguments.Contains(adjustedArgumentIdx))
                    {
                        var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                        var diagnostic = Diagnostic.Create(newRule, argument.GetExpression().GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                }

                returnState.MergeTaint(argumentState.Taint);

                //TODO: taint all objects passed as arguments
            }

            if (behavior?.PostConditions == null &&
                methodSymbol != null &&
                argumentStates != null)
            {
                for (var i = 0; i < argList.Arguments.Count; i++)
                {
                    if (i >= methodSymbol.Parameters.Length)
                    {
                        if (!methodSymbol.Parameters[methodSymbol.Parameters.Length - 1].IsParams)
                            throw new IndexOutOfRangeException();
                    }
                    else if (methodSymbol.Parameters[i].RefKind != RefKind.None)
                    {
                        argumentStates[i].MergeTaint(returnState.Taint);
                    }
                }
            }
            else
            {
                if (behavior?.PostConditions != null &&
                    behavior.PostConditions.TryGetValue(-1, out var returnPostCondition))
                {
                    if (returnPostCondition.TaintFromArguments.Count   == 1 &&
                        returnPostCondition.TaintFromArguments.First() == -1)
                    {
                        returnState = new VariableState(node, VariableTaint.Safe);
                    }
                    else if (argumentStates != null)
                    {
                        returnState = initialTaint != null && !symbol.IsStatic
                                          ? new VariableState(node, initialTaint.Value)
                                          : new VariableState(node, VariableTaint.Unset);

                        foreach (var argIdx in returnPostCondition.TaintFromArguments)
                        {
                            var adjustedArgumentIdx = isExtensionMethod ? argIdx - 1 : argIdx;
                            returnState.MergeTaint(argumentStates[adjustedArgumentIdx].Taint);
                        }
                    }

                    if (applyCustomTaint)
                        returnState.ApplyTaint(returnPostCondition.Taint);
                }

                if (argumentStates != null)
                {
                    foreach (var postCondition in behavior.PostConditions)
                    {
                        if (postCondition.Key == -1)
                            continue; // return state was already calculated

                        var adjustedPostConditionIdx = isExtensionMethod ? postCondition.Key + 1 : postCondition.Key;

                        foreach (var argIdx in postCondition.Value.TaintFromArguments)
                        {
                            var adjustedArgumentIdx = isExtensionMethod ? argIdx + 1 : argIdx;
                            argumentStates[adjustedPostConditionIdx].MergeTaint(argumentStates[adjustedArgumentIdx].Taint);
                        }

                        if (applyCustomTaint)
                            argumentStates[adjustedPostConditionIdx].ApplyTaint(postCondition.Value.Taint);
                    }
                }
            }

            if (memberVariableState != null &&
                methodSymbol        != null &&
                methodSymbol.ReturnsVoid    &&
                !methodSymbol.IsStatic      &&
                methodSymbol.Parameters.All(x => x.RefKind == RefKind.None))
            {
                memberVariableState.MergeTaint(returnState.Taint);
            }

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            return returnState;
        }

        private VariableState VisitNamedFieldInitializer(NamedFieldInitializerSyntax node, ExecutionState state, VariableState currentScope)
        {
            var assignmentState = VisitAssignment(node, node.Name, node.Expression, state);
            return MergeVariableState(node.Name, assignmentState, state, currentScope);
        }

        private VariableState VisitAssignment(VisualBasicSyntaxNode node,
                                              ExpressionSyntax      leftExpression,
                                              ExpressionSyntax      rightExpression,
                                              ExecutionState        state)
        {
            var            leftSymbol = state.GetSymbol(leftExpression);
            MethodBehavior behavior   = null;
            if (leftSymbol != null)
                behavior = leftSymbol.GetMethodBehavior(state.CachedMethodBehaviors);

            var variableState = VisitExpression(rightExpression, state);

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

            var config = ConfigurationManager.Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles);

            if (variableState.Taint != VariableTaint.Constant &&
                behavior != null &&
                // compare if all required sanitization bits are set
                ((ulong)(variableState.Taint & VariableTaint.Safe) & behavior.InjectableField) != behavior.InjectableField &&
                (variableState.Taint & (config.AuditMode ? VariableTaint.Tainted | VariableTaint.Unknown : VariableTaint.Tainted)) != 0)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection, "title_assignment");
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: taint the variable being assigned.

            return variableState;
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is NamedFieldInitializerSyntax namedFieldInitializerSyntax)
                {
                    VisitNamedFieldInitializer(namedFieldInitializerSyntax, state, finalState);
                }
                else
                {
#if DEBUG
                    Logger.Log(child.GetText().ToString().Trim() + " -> " + finalState);
#endif
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
            var result = new VariableState(expression, VariableTaint.Unset);
            var left   = VisitExpression(expression.Left, state);
            result.MergeTaint(left.Taint);
            var right = VisitExpression(expression.Right, state);
            result.MergeTaint(right.Taint);
            return result;
        }

        /// <summary>
        /// Identifier name include variable name.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            var varState = GetVariableState(expression, state);
            if (varState != null)
                return varState;

            var taintSourceState = CheckIfTaintSource(expression, state);
            if (taintSourceState != null)
                return taintSourceState;

            return ResolveVariableState(expression, state);
        }

        private VariableState VisitMemberAccessExpression(MemberAccessExpressionSyntax expression, ExecutionState state)
        {
            var varState = GetVariableState(expression, state);
            if (varState != null)
                return varState;

            var taintSourceState = CheckIfTaintSource(expression, state);
            if (taintSourceState != null)
                return taintSourceState;

            varState = ResolveVariableState(expression, state);
            if (varState.Taint != VariableTaint.Constant && expression.Expression != null)
            {
                var expressionState = VisitExpression(expression.Expression, state);
                varState.MergeTaint(expressionState.Taint);
            }

            return varState;
        }

        private VariableState CheckIfTaintSource(ExpressionSyntax expression, ExecutionState state)
        {
            var symbol   = state.GetSymbol(expression);
            var behavior = symbol?.GetMethodBehavior(state.CachedMethodBehaviors);
            if (behavior != null && behavior.PostConditions.TryGetValue(-1, out var taint))
            {
                return new VariableState(expression, (VariableTaint)taint.Taint);
            }

            return null;
        }

        private VariableState ResolveVariableState(ExpressionSyntax expression, ExecutionState state)
        {
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

                    var constantFields = ConfigurationManager.Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles)
                                                             .ConstantFields;

                    if (constantFields.Contains(field.GetTypeName()))
                    {
                        return new VariableState(expression, VariableTaint.Constant);
                    }

                    return new VariableState(expression, VariableTaint.Unknown);
                case IPropertySymbol prop:
                    if (prop.IsVirtual || prop.IsOverride || prop.IsAbstract)
                        return new VariableState(expression, VariableTaint.Unknown);

                    // TODO: Use public API
                    var syntaxNodeProperty = prop.GetMethod.GetType().GetTypeInfo().BaseType.GetTypeInfo().GetDeclaredProperty("Syntax");
                    var syntaxNode         = (VisualBasicSyntaxNode)syntaxNodeProperty?.GetValue(prop.GetMethod);
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
                finalState.MergeTaint(exprState.Taint);
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

        private VariableState MergeVariableState(ExpressionSyntax expression,
                                                 VariableState    newVariableState,
                                                 ExecutionState   state,
                                                 VariableState    currentScope = null)
        {
            var variableStateToMerge = newVariableState ?? new VariableState(expression, VariableTaint.Unset);
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                var identifier = "";
                if (expression is IdentifierNameSyntax identifierNameSyntax)
                    identifier = ResolveIdentifier(identifierNameSyntax.Identifier);
                else if (expression is MeExpressionSyntax)
                    identifier = "this";

                if (currentScope != null)
                {
                    currentScope.AddOrMergeProperty(identifier, variableStateToMerge);
                    return currentScope.PropertyStates[identifier];
                }

                state.AddOrUpdateValue(identifier, variableStateToMerge);
                return state.VariableStates[identifier];
            }

            var variableState = MergeVariableState(memberAccessExpressionSyntax.Expression, null, state, currentScope);

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
