using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Symbolic execution of C# code
    /// </summary>
    internal class CSharpCodeEvaluation
    {
        private IEnumerable<TaintAnalyzerExtensionCSharp> Extensions { get; }

        private readonly Configuration ProjectConfiguration;

        private SyntaxNodeHelper SyntaxNodeHelper;

        public CSharpCodeEvaluation(SyntaxNodeHelper syntaxHelper,
                                    Configuration projectConfiguration,
                                    IEnumerable<TaintAnalyzerExtensionCSharp> extensions)
        {
            SyntaxNodeHelper     = syntaxHelper;
            ProjectConfiguration = projectConfiguration;
            Extensions = extensions ?? Enumerable.Empty<TaintAnalyzerExtensionCSharp>();
        }

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            try
            {
                var state = new ExecutionState(ctx);

                foreach (var ext in Extensions)
                {
                    ext.VisitBegin(ctx.Node, state, ProjectConfiguration);
                }

                VisitNode(ctx.Node, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitEnd(ctx.Node, state, ProjectConfiguration);
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

        private VariableState VisitBlock(BlockSyntax node, ExecutionState state)
        {
            var lastState = new VariableState(node, VariableTaint.Unknown);
            return VisitStatements(node.Statements, state, lastState);
        }

        private VariableState VisitStatements(SyntaxList<StatementSyntax> statements, ExecutionState state, VariableState lastState)
        {
            foreach (StatementSyntax statement in statements)
            {
                var statementState = VisitNode(statement, state);
                lastState = statementState;

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state, statementState, ProjectConfiguration);
                }
            }

            return lastState;
        }

        private void TaintParameters(BaseMethodDeclarationSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }
        }

        /// <summary>
        /// Entry point that visits the method statements.
        /// </summary>
        private VariableState VisitMethodDeclaration(BaseMethodDeclarationSyntax node, ExecutionState state)
        {
            if (ProjectConfiguration.AuditMode)
            {
                TaintParameters(node, state);
            }
            else
            {
                var symbol = state.AnalysisContext.SemanticModel.GetDeclaredSymbol(node);
                if (symbol != null)
                {
                    if (symbol is IMethodSymbol methodSymbol && methodSymbol.IsStatic && methodSymbol.Name == "Main")
                        TaintParameters(node, state);
                    else if (symbol.IsTaintEntryPoint(ProjectConfiguration.TaintEntryPoints))
                        TaintParameters(node, state);
                }
            }

            if (node.Body == null)
                return new VariableState(node, VariableTaint.Unknown);

            return VisitBlock(node.Body, state);
        }

        private VariableState VisitForEach(ForEachStatementSyntax node, ExecutionState state)
        {
            state.AddNewValue(ResolveIdentifier(node.Identifier), VisitExpression(node.Expression, state));
            return VisitNode(node.Statement, state);
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
                case PrefixUnaryExpressionSyntax prefixUnaryExpression:
                    return VisitNode(prefixUnaryExpression.Operand, state);
                case LocalDeclarationStatementSyntax declarationStatementSyntax:
                    return VisitLocalDeclaration(declarationStatementSyntax, state);
                case VariableDeclarationSyntax variableDeclarationSyntax:
                    return VisitVariableDeclaration(variableDeclarationSyntax, state);
                case ExpressionStatementSyntax expressionStatementSyntax:
                    return VisitExpressionStatement(expressionStatementSyntax, state);
                case ExpressionSyntax expressionSyntax:
                    return VisitExpression(expressionSyntax, state);
                case MethodDeclarationSyntax methodDeclarationSyntax:
                    return VisitMethodDeclaration(methodDeclarationSyntax, state);
                case ConstructorDeclarationSyntax constructorDeclarationSyntax:
                    return VisitMethodDeclaration(constructorDeclarationSyntax, state);
                case DestructorDeclarationSyntax destructorDeclarationSyntax:
                    return VisitMethodDeclaration(destructorDeclarationSyntax, state);
                case PropertyDeclarationSyntax propertyDeclarationSyntax:
                    return VisitPropertyDeclaration(propertyDeclarationSyntax, state);
                case ReturnStatementSyntax returnStatementSyntax:
                    if (returnStatementSyntax.Expression == null)
                        return new VariableState(node, VariableTaint.Unknown);

                    return VisitExpression(returnStatementSyntax.Expression, state);
                case ForEachStatementSyntax forEachSyntax:
                    return VisitForEach(forEachSyntax, state);
                case BlockSyntax blockSyntax:
                    return VisitBlock(blockSyntax, state);
                case FromClauseSyntax fromClauseSyntax:
                    return VisitFromClause(fromClauseSyntax, state);
                case WhereClauseSyntax whereClauseSyntax:
                    return VisitExpression(whereClauseSyntax.Condition, state);
                case IfStatementSyntax ifStatementSyntax:
                    return VisitIf(ifStatementSyntax, state);
                case ElseClauseSyntax elseClauseSyntax:
                    return VisitNode(elseClauseSyntax.Statement, state);
                case SwitchStatementSyntax switchStatementSyntax:
                    return VisitSwitch(switchStatementSyntax, state);
                case ThrowStatementSyntax throwStatementSyntax:
                    if (throwStatementSyntax.Expression != null)
                        return VisitExpression(throwStatementSyntax.Expression, state);
                    else
                        return new VariableState(throwStatementSyntax, VariableTaint.Unknown);
                case SwitchSectionSyntax switchSectionSyntax:
                    return VisitStatements(switchSectionSyntax.Statements, state, new VariableState(node, VariableTaint.Unset));
                case BreakStatementSyntax breakStatementSyntax:
                    return new VariableState(node, VariableTaint.Constant);
                case SelectClauseSyntax selectClauseSyntax:
                    return VisitExpression(selectClauseSyntax.Expression, state);
                case QueryBodySyntax queryBodySyntax:
                    {
                        var finalState = new VariableState(queryBodySyntax, VariableTaint.Unset);

                        foreach (QueryClauseSyntax clause in queryBodySyntax.Clauses)
                        {
                            var clauseState = VisitNode(clause, state);
                            finalState.MergeTaint(clauseState.Taint);
                        }

                        if (queryBodySyntax.SelectOrGroup != null)
                        {
                            var selectState = VisitNode(queryBodySyntax.SelectOrGroup, state);
                            finalState.MergeTaint(selectState.Taint);
                        }

                        if (queryBodySyntax.Continuation != null)
                        {
                            var continuationState = VisitNode(queryBodySyntax.Continuation, state);
                            finalState.MergeTaint(continuationState.Taint);
                        }

                        return finalState;
                    }
                case TryStatementSyntax tryStatementSyntax:
                    {
                        var finalState = VisitNode(tryStatementSyntax.Block, state);

                        foreach (var c in tryStatementSyntax.Catches)
                        {
                            var catchState = VisitNode(c, state);
                            finalState.MergeTaint(catchState.Taint);
                        }

                        if (tryStatementSyntax.Finally != null)
                        {
                            var finallyState = VisitNode(tryStatementSyntax.Finally, state);
                            finalState.MergeTaint(finallyState.Taint);
                        }

                        return finalState;
                    }
                case CatchFilterClauseSyntax catchFilterClauseSyntax:
                    return VisitExpression(catchFilterClauseSyntax.FilterExpression, state);
                case CatchClauseSyntax catchClauseSyntax:
                    {
                        var finalState = new VariableState(catchClauseSyntax, VariableTaint.Unset);

                        if (catchClauseSyntax.Declaration != null)
                        {
                            var declrationState = VisitNode(catchClauseSyntax.Declaration, state);
                            finalState.MergeTaint(declrationState.Taint);
                        }

                        if (catchClauseSyntax.Filter != null)
                        {
                            var filterState = VisitNode(catchClauseSyntax.Filter, state);
                            finalState.MergeTaint(filterState.Taint);
                        }

                        var blockState = VisitNode(catchClauseSyntax.Block, state);
                        finalState.MergeTaint(blockState.Taint);

                        return finalState;
                    }
                case FinallyClauseSyntax finallyClauseSyntax:
                    return VisitNode(finallyClauseSyntax.Block, state);
                case ArrowExpressionClauseSyntax arrowExpressionClauseSyntax:
                    return VisitExpression(arrowExpressionClauseSyntax.Expression, state);
                case UsingStatementSyntax usingStatementSyntax:
                    {
                        var finalState = new VariableState(usingStatementSyntax, VariableTaint.Unset);

                        if (usingStatementSyntax.Declaration != null)
                        {
                            var declarationState = VisitNode(usingStatementSyntax.Declaration, state);
                            finalState.MergeTaint(declarationState.Taint);
                        }

                        if (usingStatementSyntax.Expression != null)
                        {
                            var expressionState = VisitExpression(usingStatementSyntax.Expression, state);
                            finalState.MergeTaint(expressionState.Taint);
                        }

                        if (usingStatementSyntax.Statement != null)
                        {
                            var catchState = VisitNode(usingStatementSyntax.Statement, state);
                            finalState.MergeTaint(catchState.Taint);
                        }

                        return finalState;
                    }
                case ForStatementSyntax forStatementSyntax:
                    {
                        var finalState = new VariableState(forStatementSyntax, VariableTaint.Unset);

                        if (forStatementSyntax.Declaration != null)
                        {
                            var declarationState = VisitNode(forStatementSyntax.Declaration, state);
                            finalState.MergeTaint(declarationState.Taint);
                        }

                        foreach (var initializer in forStatementSyntax.Initializers)
                        {
                            var initializerState = VisitNode(initializer, state);
                            finalState.MergeTaint(initializerState.Taint);
                        }

                        if (forStatementSyntax.Condition != null)
                        {
                            var conditionState = VisitExpression(forStatementSyntax.Condition, state);
                            finalState.MergeTaint(conditionState.Taint);
                        }

                        foreach (var incrementor in forStatementSyntax.Incrementors)
                        {
                            var incrementorState = VisitExpression(incrementor, state);
                            finalState.MergeTaint(incrementorState.Taint);
                        }

                        if (forStatementSyntax.Statement != null)
                        {
                            var statementState = VisitNode(forStatementSyntax.Statement, state);
                            finalState.MergeTaint(statementState.Taint);
                        }

                        return finalState;
                    }

            }

            foreach (var n in node.ChildNodes())
            {
                VisitNode(n, state);
            }

#if DEBUG
            if (Logger.IsConfigured())
                throw new Exception("Unsupported statement " + node.GetType() + " (" + node + ")");
#endif

            return new VariableState(node, VariableTaint.Unknown);
        }

        private VariableState VisitPropertyDeclaration(PropertyDeclarationSyntax propertyDeclarationSyntax, ExecutionState state)
        {
            if (propertyDeclarationSyntax.ExpressionBody != null)
                return VisitNode(propertyDeclarationSyntax.ExpressionBody, state);

            foreach (var accessor in propertyDeclarationSyntax.AccessorList.Accessors)
            {
                if (accessor.Body != null)
                    VisitBlock(accessor.Body, state);
            }

            return new VariableState(propertyDeclarationSyntax, VariableTaint.Unknown);
        }

        private VariableState VisitFromClause(FromClauseSyntax fromClauseSyntax, ExecutionState state)
        {
            var fromClauseState = VisitExpression(fromClauseSyntax.Expression, state);
            var fromSymbol      = SyntaxNodeHelper.GetSymbol(fromClauseSyntax.Expression, state.AnalysisContext.SemanticModel);
            if (fromSymbol != null)
            {
                switch (fromSymbol)
                {
                    case IPropertySymbol propertyFromSymbol when propertyFromSymbol.Type.IsTaintType(ProjectConfiguration.Behavior):
                    case IFieldSymbol fieldFromSymbol when fieldFromSymbol.Type.IsTaintType(ProjectConfiguration.Behavior):
                        return new VariableState(fromClauseSyntax, VariableTaint.Tainted);
                }
            }

            return fromClauseState;
        }

        private VariableState VisitSwitch(SwitchStatementSyntax switchStatementSyntax, ExecutionState state)
        {
            var exprVarState = VisitExpression(switchStatementSyntax.Expression, state);
            if (switchStatementSyntax.Sections.Count <= 0)
                return exprVarState;

            var firstCaseState  = new ExecutionState(state);
            var sectionVarState = VisitNode(switchStatementSyntax.Sections[0], firstCaseState);
            exprVarState.MergeTaint(sectionVarState.Taint);

            for (var i = 1; i < switchStatementSyntax.Sections.Count; i++)
            {
                var section   = switchStatementSyntax.Sections[i];
                var caseState = new ExecutionState(state);
                sectionVarState = VisitNode(section, caseState);
                exprVarState.MergeTaint(sectionVarState.Taint);
                firstCaseState.Merge(caseState);
            }

            if (switchStatementSyntax.Sections.Any(section => section.Labels.Any(label => label.Kind() == SyntaxKind.DefaultSwitchLabel)))
                state.Replace(firstCaseState);
            else
                state.Merge(firstCaseState);

            return exprVarState;
        }

        private VariableState VisitIf(IfStatementSyntax ifStatementSyntax, ExecutionState state)
        {
            var condition = VisitExpression(ifStatementSyntax.Condition, state);

            var ifState     = new ExecutionState(state);
            var ifStatement = VisitNode(ifStatementSyntax.Statement, ifState);
            condition.MergeTaint(ifStatement.Taint);

            if (ifStatementSyntax.Else != null)
            {
                var elseState     = new ExecutionState(state);
                var elseStatement = VisitNode(ifStatementSyntax.Else, elseState);
                condition.MergeTaint(elseStatement.Taint);

                var @else = ifStatementSyntax.Else;
                while (@else?.Statement != null && @else.Statement is IfStatementSyntax elseIf)
                {
                    @else = elseIf.Else;
                }

                if (@else != null)
                {
                    ifState.Merge(elseState);
                    state.Replace(ifState);
                    return condition;
                }
                else
                {
                    state.Merge(elseState);
                }
            }

            state.Merge(ifState);
            return condition;
        }

        /// <summary>
        /// Unwrap
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            return VisitVariableDeclaration(declaration.Declaration, state);
        }

        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclarationSyntax declaration, ExecutionState state)
        {
            var lastState = new VariableState(declaration, VariableTaint.Unknown);

            foreach (var variable in declaration.Variables)
            {
                VariableState varState;
                if (variable.Initializer != null)
                {
                    varState = VisitExpression(variable.Initializer.Value, state);
                    var type = state.AnalysisContext.SemanticModel.GetTypeInfo(variable.Initializer.Value);

                    if (type.ConvertedType != null && (type.ConvertedType == state.StringType || type.ConvertedType.IsValueType))
                    {
                        var copy = new VariableState(varState.Node, varState.Taint, varState.Value);
                        foreach (var property in varState.PropertyStates)
                        {
                            copy.AddProperty(property.Key, property.Value);
                        }

                        varState = copy;
                    }
                }
                else
                {
                    varState = new VariableState(variable, VariableTaint.Constant);
                }

                state.AddNewValue(ResolveIdentifier(variable.Identifier), varState);
                lastState = varState;
            }

            return lastState;
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

        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            switch (expression)
            {
                case ParenthesizedExpressionSyntax parenthesizedExpressionSyntax:
                    return VisitExpression(parenthesizedExpressionSyntax.Expression, state);
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    return VisitMethodInvocation(invocationExpressionSyntax, state);
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    return VisitObjectCreation(objectCreationExpressionSyntax, state);
                case LiteralExpressionSyntax literalExpressionSyntax:
                    return new VariableState(literalExpressionSyntax, VariableTaint.Constant, literalExpressionSyntax.Token.Value);
                case IdentifierNameSyntax identifierNameSyntax:
                    return VisitIdentifierName(identifierNameSyntax, state);
                case BinaryExpressionSyntax binaryExpressionSyntax:
                {
                    switch (binaryExpressionSyntax.Kind())
                    {
                        case SyntaxKind.AsExpression:
                        case SyntaxKind.IsExpression:
                            return VisitNode(binaryExpressionSyntax.Left, state);
                    }

                    return VisitBinaryExpression(binaryExpressionSyntax, binaryExpressionSyntax.Left, binaryExpressionSyntax.Right, state);
                }
                case AssignmentExpressionSyntax assignmentExpressionSyntax:
                    if (assignmentExpressionSyntax.Kind() != SyntaxKind.SimpleAssignmentExpression)
                    {
                        var left = VisitExpression(assignmentExpressionSyntax.Left, state);
                        var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                        left.MergeTaint(assignmentState.Taint);
                        return left;
                    }
                    else
                    {
                        var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                        return MergeVariableState(assignmentExpressionSyntax.Left, assignmentState, state);
                    }

                case MemberAccessExpressionSyntax memberAccessExpressionSyntax:
                    return VisitMemberAccessExpression(memberAccessExpressionSyntax, state);
                case ElementAccessExpressionSyntax elementAccessExpressionSyntax:
                    return VisitElementAccess(elementAccessExpressionSyntax, elementAccessExpressionSyntax.ArgumentList, state);
                case ArrayCreationExpressionSyntax arrayCreationExpressionSyntax:
                    return VisitArrayCreation(arrayCreationExpressionSyntax, arrayCreationExpressionSyntax.Initializer, state);
                case ImplicitArrayCreationExpressionSyntax implicitArrayCreationExpressionSyntax:
                    return VisitArrayCreation(implicitArrayCreationExpressionSyntax, implicitArrayCreationExpressionSyntax.Initializer, state);
                case TypeOfExpressionSyntax typeOfExpressionSyntax:
                    return new VariableState(typeOfExpressionSyntax, VariableTaint.Safe);
                case ConditionalExpressionSyntax conditionalExpressionSyntax:
                {
                    VisitExpression(conditionalExpressionSyntax.Condition, state);
                    var finalState = new VariableState(conditionalExpressionSyntax, VariableTaint.Unset);

                    var whenTrueState = VisitExpression(conditionalExpressionSyntax.WhenTrue, state);
                    finalState.MergeTaint(whenTrueState.Taint);
                    var whenFalseState = VisitExpression(conditionalExpressionSyntax.WhenFalse, state);
                    finalState.MergeTaint(whenFalseState.Taint);

                    return finalState;
                }
                case CheckedExpressionSyntax checkedExpressionSyntax:
                    return VisitExpression(checkedExpressionSyntax.Expression, state);
                case QueryExpressionSyntax queryExpressionSyntax:
                {
                    var finalState = new VariableState(queryExpressionSyntax, VariableTaint.Unset);
                    var fromState = VisitNode(queryExpressionSyntax.FromClause, state);
                    finalState.MergeTaint(fromState.Taint);
                    var bodyState = VisitNode(queryExpressionSyntax.Body, state);
                    finalState.MergeTaint(bodyState.Taint);
                    return finalState;
                }
                case InterpolatedStringExpressionSyntax interpolatedStringExpressionSyntax:
                    return VisitInterpolatedString(interpolatedStringExpressionSyntax, state);
                case CastExpressionSyntax castExpressionSyntax:
                    return VisitExpression(castExpressionSyntax.Expression, state);
                case DefaultExpressionSyntax defaultExpressionSyntax:
                    var value = state.AnalysisContext.SemanticModel.GetConstantValue(defaultExpressionSyntax);
                    return new VariableState(defaultExpressionSyntax, VariableTaint.Constant, value.HasValue ? value.Value : null);
                case PrefixUnaryExpressionSyntax prefixUnaryExpressionSyntax:
                    return VisitExpression(prefixUnaryExpressionSyntax.Operand, state);
                case PostfixUnaryExpressionSyntax postfixUnaryExpressionSyntax:
                    return VisitExpression(postfixUnaryExpressionSyntax.Operand, state);
                case AwaitExpressionSyntax awaitSyntax:
                    return VisitExpression(awaitSyntax.Expression, state);
                case ThisExpressionSyntax thisExpressionSyntax:
                    return new VariableState(thisExpressionSyntax, VariableTaint.Unknown);
                case PredefinedTypeSyntax predefinedTypeSyntax:
                    return new VariableState(predefinedTypeSyntax, VariableTaint.Unknown);
                case AnonymousObjectCreationExpressionSyntax anonymousObjectCreationExpressionSyntax:
                    {
                        var finalState = new VariableState(anonymousObjectCreationExpressionSyntax, VariableTaint.Unset);
                        foreach (AnonymousObjectMemberDeclaratorSyntax initializer in anonymousObjectCreationExpressionSyntax.Initializers)
                        {
                            var initializerState = VisitExpression(initializer.Expression, state);
                            finalState.MergeTaint(initializerState.Taint);
                        }

                        return finalState;
                    }
            }
#if DEBUG
            if (Logger.IsConfigured())
                throw new Exception("Unsupported expression " + expression.GetType() + " (" + expression + ")");
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
                varState.MergeTaint(IsSafeTypeAsString(state, interpolation.Expression) ? VariableTaint.Safe : expressionState.Taint);
            }

            return varState;
        }

        private VariableState VisitElementAccess(ElementAccessExpressionSyntax elementAccess,
                                                 BracketedArgumentListSyntax   argumentList,
                                                 ExecutionState                state)
        {
            var finalState = new VariableState(elementAccess, VariableTaint.Unset);

            foreach (var argument in argumentList.Arguments)
            {
                finalState.MergeTaint(VisitExpression(argument.Expression, state).Taint);
            }

            finalState.MergeTaint(VisitExpression(elementAccess.Expression, state).Taint);

            var taintSourceState = CheckIfTaintSource(elementAccess, state);
            if (taintSourceState != null)
                finalState.MergeTaint(taintSourceState.Taint);

            return finalState;
        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            VariableState memberVariableState = null;
            if (node.Expression is MemberAccessExpressionSyntax memberAccessExpression)
            {
                memberVariableState = VisitExpression(memberAccessExpression.Expression, state);
            }

            return VisitInvocationAndCreation(node, node.ArgumentList, state, memberVariableState?.Taint, memberVariableState);
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);
            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is AssignmentExpressionSyntax assignmentExpressionSyntax)
                {
                    var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                    MergeVariableState(assignmentExpressionSyntax.Left, assignmentState, state, finalState);
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

        private VariableState VisitArrayCreation(SyntaxNode node, InitializerExpressionSyntax arrayInit, ExecutionState state)
        {
            var finalState = new VariableState(node, VariableTaint.Safe);
            if (arrayInit == null)
                return finalState;

            foreach (var ex in arrayInit.Expressions)
            {
                var exprState = VisitExpression(ex, state);
                finalState.MergeTaint(exprState.Taint);
            }

            return finalState;
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

        private IReadOnlyDictionary<int, PostCondition> GetPostConditions(MethodBehavior behavior, bool isExtensionMethod, ArgumentListSyntax argList, ExecutionState state)
        {
            if (behavior.Conditions == null)
                return behavior.PostConditions;

            foreach (var condition in behavior.Conditions)
            {
                if (CheckPrecondition(condition.If, isExtensionMethod, argList, state))
                    return condition.Then;
            }

            return behavior.PostConditions;
        }

        private bool CheckPrecondition(IReadOnlyDictionary<int, object> condition, bool isExtensionMethod, ArgumentListSyntax argList, ExecutionState state)
        {
            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument            = argList.Arguments[i];
                var adjustedArgumentIdx = isExtensionMethod ? i + 1 : i;

                if (!condition.TryGetValue(adjustedArgumentIdx, out var preconditionArgumentValue))
                {
                    continue;
                }

                var calculatedArgumentValue = state.AnalysisContext.SemanticModel.GetConstantValue(argument.Expression);
                if (calculatedArgumentValue.HasValue && calculatedArgumentValue.Value.Equals(preconditionArgumentValue))
                {
                    continue;
                }

                return false;
            }

            return true;
        }

        /// <summary>
        /// The map is used to store variable states while evaluating function arguments in a loop.
        /// Then stored values are used to apply post conditions like "apply taint from 3rd argument to 1st argument"
        /// </summary>
        private Dictionary<int, VariableState> CreateArgStatesMapIfNeeded(ArgumentListSyntax                      argList,
                                                                          IMethodSymbol                           methodSymbol,
                                                                          IReadOnlyDictionary<int, PostCondition> postConditions)
        {
            if (argList == null)
                return null;

            if (argList.Arguments.Count < 1)
                return null;

            if (methodSymbol != null && methodSymbol.Parameters.Any(x => x.RefKind != RefKind.None))
                return new Dictionary<int, VariableState>(argList.Arguments.Count);

            if (postConditions == null)
                return null;

            if (postConditions.Any(c => c.Key != (int)ArgumentIndex.Returns &&
                                        c.Key != (int)ArgumentIndex.This &&
                                        (c.Value.Taint != 0ul || c.Value.TaintFromArguments.Any())))
            {
                return new Dictionary<int, VariableState>(argList.Arguments.Count);
            }

            return null;
        }

        private VariableState CreateInitialReturnState(VariableTaint?       initialTaint,
                                                       ISymbol              symbol,
                                                       ExpressionSyntax     node,
                                                       ArgumentListSyntax   argList,
                                                       MethodBehavior       behavior)
        {
            if (initialTaint != null && !symbol.IsStatic)
                return new VariableState(node, initialTaint.Value);

            VariableTaint taint = argList?.Arguments.Count > 0 && behavior != null ? VariableTaint.Unset : VariableTaint.Unknown;
            return new VariableState(node, taint);
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
                                                         VariableState      memberVariableState = null)
        {
            var symbol = state.GetSymbol(node);
            if (symbol == null)
            {
                var constValue = state.AnalysisContext.SemanticModel.GetConstantValue(node);
                if (constValue.HasValue)
                    return new VariableState(node, VariableTaint.Constant);
                else
                    return new VariableState(node, initialTaint ?? VariableTaint.Unknown);
            }

            var  methodSymbol      = symbol as IMethodSymbol;
            bool isExtensionMethod = methodSymbol?.ReducedFrom != null;
            var  behavior          = symbol.GetMethodBehavior(ProjectConfiguration.Behavior);
            IReadOnlyDictionary<int, PostCondition> postConditions = null;
            if (behavior != null)
                postConditions = GetPostConditions(behavior, isExtensionMethod, argList, state);

            PostCondition returnPostCondition = null;
            postConditions?.TryGetValue((int)ArgumentIndex.Returns, out returnPostCondition);

            PostCondition thisPostCondition = null;
            postConditions?.TryGetValue((int)ArgumentIndex.This, out thisPostCondition);

            VariableState                  returnState    = CreateInitialReturnState(initialTaint, symbol, node, argList, behavior);
            Dictionary<int, VariableState> argumentStates = CreateArgStatesMapIfNeeded(argList, methodSymbol, postConditions);
            VariableState thisState                       = memberVariableState != null ? memberVariableState : new VariableState(node, VariableTaint.Unknown);

            var behaviorApplies = behavior != null && BehaviorApplies(behavior.AppliesUnderCondition, methodSymbol, argList?.Arguments, state);

            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument      = argList.Arguments[i];
                var argumentState = VisitExpression(argument.Expression, state);

                var adjustedArgumentIdx = methodSymbol?.FindArgumentIndex(i, argument) ?? i;
                if (isExtensionMethod)
                    ++adjustedArgumentIdx;

                if (argumentStates != null)
                    argumentStates[adjustedArgumentIdx] = argumentState;

#if DEBUG
                Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
#endif
                if (behaviorApplies)
                {
                    if ((argumentState.Taint & (ProjectConfiguration.AuditMode
                                                    ? VariableTaint.Tainted | VariableTaint.Unknown
                                                    : VariableTaint.Tainted)) != 0)
                    {
                        //If the current parameter can be injected.
                        if (behavior.InjectableArguments.TryGetValue(adjustedArgumentIdx, out var injectableArgument) &&
                            (injectableArgument.RequiredTaintBits & (ulong)argumentState.Taint) != injectableArgument.RequiredTaintBits)
                        {
                            var newRule    = LocaleUtil.GetDescriptor(injectableArgument.Locale);
                            var diagnostic = Diagnostic.Create(newRule, argument.Expression.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                            state.AnalysisContext.ReportDiagnostic(diagnostic);
                        }
                    }
                    else if (argumentState.Taint == VariableTaint.Constant)
                    {
                        if (behavior.InjectableArguments.TryGetValue(adjustedArgumentIdx, out var injectableArgument) &&
                            injectableArgument.Not && (injectableArgument.RequiredTaintBits & (ulong)argumentState.Taint) != 0ul)
                        {
                            var newRule    = LocaleUtil.GetDescriptor(injectableArgument.Locale);
                            var diagnostic = Diagnostic.Create(newRule, argument.Expression.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                            state.AnalysisContext.ReportDiagnostic(diagnostic);
                        }
                    }
                }

                var argumentToSearch = adjustedArgumentIdx;
                if (methodSymbol != null                           &&
                    i            >= methodSymbol.Parameters.Length &&
                    methodSymbol.Parameters[methodSymbol.Parameters.Length - 1].IsParams)
                {
                    argumentToSearch = isExtensionMethod ? methodSymbol.Parameters.Length : methodSymbol.Parameters.Length - 1;
                }

                if (returnPostCondition == null ||
                    returnPostCondition.TaintFromArguments.Contains(argumentToSearch))
                {
                    returnState.MergeTaint(argumentState.Taint);
                }

                if (thisPostCondition?.TaintFromArguments.Contains(argumentToSearch) == true)
                {
                    thisState.MergeTaint(argumentState.Taint);
                }

                //TODO: taint all objects passed as arguments
                //if (argument.Expression is IdentifierNameSyntax identifierNameSyntax)
                //{
                //    var argumentType = state.AnalysisContext.SemanticModel.GetTypeInfo(argument.Expression).Type;
                //    if (argumentType.IsReferenceType &&
                //        argumentType == state.StringType) // string is immutable
                //    {
                //        state.MergeValue(ResolveIdentifier(identifierNameSyntax.Identifier),
                //                         argumentState.Merge(new VariableState(argument, VariableTaint.Unknown)));
                //    }
                //}
            }

            if (returnPostCondition != null)
            {
                if (returnPostCondition.TaintFromArguments.Contains((int)ArgumentIndex.This))
                {
                    returnState.MergeTaint(thisState.Taint);
                }
                else
                {
                    returnState.ApplyTaint(returnPostCondition.Taint);
                }
            }

            if (argumentStates != null)
            {
                foreach(var arg in argumentStates)
                {
                    if (postConditions != null && postConditions.TryGetValue(arg.Key, out var postCondition))
                    {
                        foreach (var argIdx in postCondition.TaintFromArguments)
                        {
                            if (isExtensionMethod && argIdx == 0)
                            {
                                arg.Value.MergeTaint(initialTaint.Value); // shouldn't be null, otherwise fail early
                                continue;
                            }

                            if (!argumentStates.TryGetValue(argIdx, out var postConditionStateSource))
                                continue;

                            arg.Value.MergeTaint(postConditionStateSource.Taint);
                        }

                        arg.Value.ApplyTaint(postCondition.Taint);
                    }
                    else if (methodSymbol != null)
                    {
                        var adjustedArgIx = isExtensionMethod ? arg.Key - 1 : arg.Key;

                        if (adjustedArgIx < methodSymbol.Parameters.Length)
                        {
                            if (methodSymbol.Parameters[adjustedArgIx].RefKind != RefKind.None)
                                arg.Value.MergeTaint(returnState.Taint);
                        }
                        else if (!methodSymbol.Parameters[methodSymbol.Parameters.Length - 1].IsParams)
                            throw new IndexOutOfRangeException();
                    }
                }
            }

            // Some defaults if no behavior is specified:
            // Apply taint to `this` if non-static void method without ref/out parameters
            if (thisPostCondition == null &&
                methodSymbol != null      &&
                methodSymbol.ReturnsVoid  &&
                !methodSymbol.IsStatic    &&
                methodSymbol.Parameters.All(x => x.RefKind == RefKind.None))
            {
                thisState.MergeTaint(returnState.Taint);
            }

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state, ProjectConfiguration);
            }

            return returnState;
        }

        private bool BehaviorApplies(IReadOnlyDictionary<object, object> condition, IMethodSymbol methodSymbol, SeparatedSyntaxList<ArgumentSyntax>? args, ExecutionState state)
        {
            if (condition == null || methodSymbol == null || condition.Count == 0)
                return true;

            var ps = methodSymbol.Parameters;

            foreach (var kv in condition)
            {
                var ix = (int)kv.Key;
                var valDict = (IReadOnlyDictionary<object, object>)kv.Value;
                var expectedVal = valDict["Value"];

                object codeVal = null;

                // fill in the default
                if(ix < ps.Length)
                {
                    var p = ps[ix];

                    if (p.HasExplicitDefaultValue)
                        codeVal = p.ExplicitDefaultValue;
                }

                // look at each arg, figure out if it changes the default
                if (args != null)
                {
                    var lexicalIx = 0;
                    foreach (var arg in args)
                    {
                        var destIx = methodSymbol?.FindArgumentIndex(lexicalIx, arg) ?? lexicalIx;

                        if (destIx == ix)
                        {
                            var val = state.AnalysisContext.SemanticModel.GetConstantValue(arg.Expression);
                            if (val.HasValue)
                                codeVal = val.Value;

                            break;
                        }

                        lexicalIx++;
                    }
                }

                if (!expectedVal.Equals(codeVal))
                    return false;
            }

            return true;
        }

        private VariableState VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state)
        {
            var            leftSymbol = state.GetSymbol(node.Left);
            MethodBehavior behavior   = null;
            if (leftSymbol != null)
                behavior = leftSymbol.GetMethodBehavior(ProjectConfiguration.Behavior);

            var variableState = VisitExpression(node.Right, state);

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitAssignment(node, state, behavior, leftSymbol, variableState, ProjectConfiguration);
            }

            //if (leftSymbol != null)
            //{
            //    var rightTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(node.Right).Type;
            //    if (rightTypeSymbol == null)
            //        return new VariableState(node.Right, VariableTaint.Unknown);

            //    var leftTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(node.Left).Type;
            //    if (!state.AnalysisContext.SemanticModel.Compilation.ClassifyConversion(rightTypeSymbol, leftTypeSymbol).IsImplicit)
            //        return new VariableState(node.Right, VariableTaint.Unknown);
            //}

            if (variableState.Taint != VariableTaint.Constant &&
                behavior != null &&
                // compare if all required sanitization bits are set
                ((ulong)(variableState.Taint & VariableTaint.Safe) & behavior.InjectableField.RequiredTaintBits) != behavior.InjectableField.RequiredTaintBits &&
                (variableState.Taint & (ProjectConfiguration.AuditMode ? VariableTaint.Tainted | VariableTaint.Unknown : VariableTaint.Tainted)) != 0)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.InjectableField.Locale, "title_assignment");
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: taint the variable being assigned.

            return variableState;
        }

        private VariableState GetVariableState(ExpressionSyntax expression, ExecutionState state)
        {
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                VariableState result;
                if (!(expression is IdentifierNameSyntax identifierNameSyntax))
                {
                    //TODO: How to correctly handle "this" case
                    if (expression is ThisExpressionSyntax && state.VariableStates.TryGetValue("this", out result))
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
                else if (expression is ThisExpressionSyntax)
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
            variableState.AddOrMergeProperty(stateIdentifier, variableStateToMerge);
            return variableState.PropertyStates[stateIdentifier];
        }

        private VariableState VisitIdentifierName(ExpressionSyntax expression, ExecutionState state)
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
            var varState = VisitIdentifierName(expression, state);

            if (varState.Taint != VariableTaint.Unknown || expression.Expression == null)
            {
                return varState;
            }

            var expressionState = VisitExpression(expression.Expression, state);
            varState.MergeTaint(expressionState.Taint);
            expressionState.AddOrMergeProperty(ResolveIdentifier(expression.Name.Identifier), varState);

            return varState;
        }

        private VariableState CheckIfTaintSource(ExpressionSyntax expression, ExecutionState state)
        {
            var symbol   = state.GetSymbol(expression);
            var behavior = symbol?.GetMethodBehavior(ProjectConfiguration.Behavior);
            if (behavior != null && behavior.PostConditions.TryGetValue((int)ArgumentIndex.Returns, out var taint))
            {
                return new VariableState(expression, (VariableTaint)taint.Taint);
            }

            return null;
        }

        private VariableState ResolveVariableState(ArrowExpressionClauseSyntax arrowExpressionClauseSyntax,
                                                   ExpressionSyntax expression,
                                                   SemanticModel possiblyOtherSemanticModel,
                                                   ref HashSet<ExpressionSyntax> visited)
        {
            if (possiblyOtherSemanticModel.GetConstantValue(arrowExpressionClauseSyntax.Expression).HasValue)
                return new VariableState(expression, VariableTaint.Constant);

            if (visited == null)
                visited = new HashSet<ExpressionSyntax>();
            else if (!visited.Add(arrowExpressionClauseSyntax.Expression))
                return new VariableState(expression, VariableTaint.Unknown);

            return ResolveVariableState(arrowExpressionClauseSyntax.Expression,
                                        null,
                                        possiblyOtherSemanticModel,
                                        visited);
        }

        private VariableState ResolveVariableState(ExpressionSyntax expression,
                                                   ExecutionState state,
                                                   SemanticModel semanticModel = null,
                                                   HashSet<ExpressionSyntax> visited = null)
        {
            semanticModel = semanticModel ?? state.AnalysisContext.SemanticModel;
            var symbol    = semanticModel.GetSymbolInfo(expression).Symbol;
            switch (symbol)
            {
                case null:
                return new VariableState(expression, VariableTaint.Unknown);
                case IFieldSymbol field:
                if (field.IsConst)
                    return new VariableState(expression, VariableTaint.Constant);

                if (!field.IsReadOnly)
                    return new VariableState(expression, VariableTaint.Unknown);

                if (ProjectConfiguration.ConstantFields.Contains(field.GetTypeName()))
                {
                    return new VariableState(expression, VariableTaint.Constant);
                }

                return new VariableState(expression, VariableTaint.Unknown);
                case IPropertySymbol prop:
                if (prop.IsVirtual || prop.IsOverride || prop.IsAbstract)
                    return new VariableState(expression, VariableTaint.Unknown);

                var getMtd = prop.GetMethod;
                if (getMtd == null)
                {
                    return new VariableState(expression, VariableTaint.Unknown);
                }

                var decls = getMtd.DeclaringSyntaxReferences;
                if (decls.Length != 1)
                {
                    // partial methods can't return anything, so something weird is going on
                    return new VariableState(expression, VariableTaint.Unknown);
                }

                var syntaxNode = (CSharpSyntaxNode)decls[0].GetSyntax();
                if (syntaxNode == null)
                    return new VariableState(expression, VariableTaint.Unknown);

                if (!semanticModel.Compilation.ContainsSyntaxTree(syntaxNode.SyntaxTree))
                    return new VariableState(expression, VariableTaint.Unknown);

                var possiblyOtherSemanticModel = semanticModel.Compilation.GetSemanticModel(syntaxNode.SyntaxTree);
                if (syntaxNode is ArrowExpressionClauseSyntax arrowExpressionClauseSyntax)
                    return ResolveVariableState(arrowExpressionClauseSyntax, expression, possiblyOtherSemanticModel, ref visited);

                if (syntaxNode is AccessorDeclarationSyntax accessorDecl)
                {
                    if (accessorDecl.Body != null)
                    {
                        var accessFlow = possiblyOtherSemanticModel.AnalyzeControlFlow(accessorDecl.Body);
                        if (accessFlow.Succeeded && AllReturnConstant(accessFlow.ExitPoints, possiblyOtherSemanticModel, visited))
                            return new VariableState(expression, VariableTaint.Constant);
                    }

                    return new VariableState(expression, VariableTaint.Unknown);
                }

                if (!(syntaxNode is StatementSyntax statementSyntax))
                    return new VariableState(expression, VariableTaint.Unknown);

                var flow = possiblyOtherSemanticModel.AnalyzeControlFlow(statementSyntax);

                if (flow.Succeeded && AllReturnConstant(flow.ExitPoints, possiblyOtherSemanticModel, visited))
                {
                    return new VariableState(expression, VariableTaint.Constant);
                }

                return new VariableState(expression, VariableTaint.Unknown);
            }

            return new VariableState(expression, VariableTaint.Unknown);
        }

        private bool AllReturnConstant(ImmutableArray<SyntaxNode> exitPoints, SemanticModel semanticModel, HashSet<ExpressionSyntax> visited)
        {
            foreach (var exitPoint in exitPoints)
            {
                if (!(exitPoint is ReturnStatementSyntax returnStatementSyntax))
                    return false;

                if (semanticModel.GetConstantValue(returnStatementSyntax.Expression).HasValue)
                {
                    continue;
                }

                if (visited == null)
                    visited = new HashSet<ExpressionSyntax>();
                else if (!visited.Add(returnStatementSyntax.Expression))
                    return false;

                if (ResolveVariableState(returnStatementSyntax.Expression, null, semanticModel, visited).Taint != VariableTaint.Constant)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(ExpressionSyntax expression,
                                                    ExpressionSyntax leftExpression,
                                                    ExpressionSyntax rightExpression,
                                                    ExecutionState state)
        {
            var result = new VariableState(expression, VariableTaint.Unset);
            var left = VisitExpression(leftExpression, state);
            var right = VisitExpression(rightExpression, state);

            // Detect implicit conversions to string through concatenation
            // with the binary Add operator.
            if (expression.Kind() == SyntaxKind.AddExpression &&
                ReferenceEquals(state.AnalysisContext.SemanticModel.GetTypeInfo(expression).ConvertedType, state.StringType))
            {
                // We only do this check if one side is a string
                // and the other side is not.
                bool leftIsString = ReferenceEquals(state.AnalysisContext.SemanticModel.GetTypeInfo(leftExpression).Type, state.StringType);
                bool rightIsString = ReferenceEquals(state.AnalysisContext.SemanticModel.GetTypeInfo(rightExpression).Type, state.StringType);
                if (leftIsString != rightIsString)
                {
                    if (!leftIsString)
                    {
                        result.MergeTaint(IsSafeTypeAsString(state, leftExpression) ? VariableTaint.Safe : left.Taint);
                        result.MergeTaint(right.Taint);
                    }
                    else
                    {
                        result.MergeTaint(left.Taint);
                        result.MergeTaint(IsSafeTypeAsString(state, rightExpression) ? VariableTaint.Safe : right.Taint);
                    }

                    return result;
                }
            }

            result.MergeTaint(left.Taint);
            result.MergeTaint(right.Taint);

            return result;
        }

        /// <summary>
        /// Determines if an expression is safe if converted to a string.
        /// </summary>
        /// <param name="state">The current execution state.</param>
        /// <param name="expression">The expression being evaluated.</param>
        /// <returns><see langword="true"/> if <paramref name="expression"/> is considered
        /// safe when converted to its string representation, otherwise <see langword="false"/>.</returns>
        private bool IsSafeTypeAsString(ExecutionState state, ExpressionSyntax expression)
        {
            ITypeSymbol type = state.AnalysisContext.SemanticModel.GetTypeInfo(expression).Type;
            return !ReferenceEquals(type, state.StringType) && !ReferenceEquals(type, state.ObjectType);
        }
    }
}
