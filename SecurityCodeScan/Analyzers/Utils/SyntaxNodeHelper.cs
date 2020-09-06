#nullable disable
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Utils
{
    public abstract class SyntaxNodeHelper
    {
        [System.Flags]
        protected enum CallKind
        {
            None = 0,
            Invocation = 1,
            ObjectCreation = 2, // a constructor call
            AnyCall = Invocation | ObjectCreation,
        }

        public abstract IMethodSymbol GetCallerMethodSymbol(SyntaxNode node, SemanticModel semanticModel);
        public abstract ITypeSymbol GetEnclosingTypeSymbol(SyntaxNode node, SemanticModel semanticModel);
        public abstract ITypeSymbol GetClassDeclarationTypeSymbol(SyntaxNode node, SemanticModel semanticModel);
        public abstract SyntaxNode GetAssignmentLeftNode(SyntaxNode node);
        public abstract string GetAssignmentLeftNodeName(SyntaxNode node);
        public abstract SyntaxNode GetAssignmentRightNode(SyntaxNode node);
        public abstract SyntaxNode GetMemberAccessNameNode(SyntaxNode node);
        public abstract SyntaxNode GetMemberAccessExpressionNode(SyntaxNode node);
        public abstract SyntaxNode GetInvocationExpressionNode(SyntaxNode node);
        public abstract SyntaxNode GetDefaultValueForAnOptionalParameter(SyntaxNode declNode, int paramIndex);
        public abstract SyntaxNode GetAttributeArgumentExpressionNode(SyntaxNode node);

        public abstract IEnumerable<SyntaxNode> GetObjectInitializerExpressionNodes(SyntaxNode node);

        /// <summary>This will return true if the SyntaxNode is either InvocationExpression or ObjectCreationExpression (in C# or VB)</summary>
        public abstract bool IsMethodInvocationNode(SyntaxNode node);
        public abstract bool IsSimpleMemberAccessExpressionNode(SyntaxNode node);
        public abstract bool IsObjectCreationExpressionNode(SyntaxNode node);
        protected abstract IEnumerable<SyntaxNode> GetCallArgumentExpressionNodes(SyntaxNode node, CallKind callKind);
        public abstract IEnumerable<SyntaxNode> GetDescendantAssignmentExpressionNodes(SyntaxNode node);
        public abstract IEnumerable<SyntaxNode> GetDescendantMemberAccessExpressionNodes(SyntaxNode node);
        public abstract IEnumerable<SyntaxNode> GetDeclarationAttributeNodes(SyntaxNode node);
        public abstract IEnumerable<SyntaxNode> GetAttributeArgumentNodes(SyntaxNode node);
        public abstract bool IsAttributeArgument(SyntaxNode node);
        public abstract SyntaxNode GetAttributeArgumentNode(SyntaxNode node);
        
        /// <summary> returns true if node is an ObjectCreationExpression and is under a FieldDeclaration node</summary>
        public abstract bool IsObjectCreationExpressionUnderFieldDeclaration(SyntaxNode node);

        /// <summary>
        /// returns the ancestor VariableDeclarator node for an ObjectCreationExpression if 
        /// IsObjectCreationExpressionUnderFieldDeclaration(node) returns true, return null otherwise.
        ///</summary>
        public abstract SyntaxNode GetVariableDeclaratorOfAFieldDeclarationNode(SyntaxNode objectCreationExpression);

        public abstract bool IsObjectConstructionForTemporaryObject(SyntaxNode node);


        public ISymbol GetEnclosingConstructSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            ISymbol symbol = GetCallerMethodSymbol(node, semanticModel);

            if (symbol == null)
            {
                symbol = GetEnclosingTypeSymbol(node, semanticModel);
            }

            return symbol;
        }

        public IEnumerable<SyntaxNode> GetCallArgumentExpressionNodes(SyntaxNode node)
        {
            return GetCallArgumentExpressionNodes(node, CallKind.AnyCall);
        }

        public IEnumerable<SyntaxNode> GetInvocationArgumentExpressionNodes(SyntaxNode node)
        {
            return GetCallArgumentExpressionNodes(node, CallKind.Invocation);
        }

        public IEnumerable<SyntaxNode> GetObjectCreationArgumentExpressionNodes(SyntaxNode node)
        {
            return GetCallArgumentExpressionNodes(node, CallKind.ObjectCreation);
        }

        public abstract IMethodSymbol GetCalleeMethodSymbol(SyntaxNode node, SemanticModel semanticModel);

        public static IEnumerable<IMethodSymbol> GetCandidateCalleeMethodSymbols(SyntaxNode node, SemanticModel semanticModel)
        {
            foreach (ISymbol symbol in GetCandidateReferencedSymbols(node, semanticModel))
            {
                if (symbol != null && symbol.Kind == SymbolKind.Method)
                {
                    yield return (IMethodSymbol)symbol;
                }
            }
        }

        public IEnumerable<IMethodSymbol> GetCalleeMethodSymbols(SyntaxNode node, SemanticModel semanticModel)
        {
            IMethodSymbol symbol = GetCalleeMethodSymbol(node, semanticModel);
            if (symbol != null)
            {
                return new List<IMethodSymbol> { symbol };
            }

            return GetCandidateCalleeMethodSymbols(node, semanticModel);
        }

        public static IPropertySymbol GetCalleePropertySymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            ISymbol symbol = GetReferencedSymbol(node, semanticModel);
            if (symbol != null && symbol.Kind == SymbolKind.Property)
            {
                return (IPropertySymbol)symbol;
            }

            return null;
        }

        public static IFieldSymbol GetCalleeFieldSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            ISymbol symbol = GetReferencedSymbol(node, semanticModel);
            if (symbol != null && symbol.Kind == SymbolKind.Field)
            {
                return (IFieldSymbol)symbol;
            }

            return null;
        }

        public static ISymbol GetSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            return GetDeclaredSymbol(node, semanticModel) ?? GetReferencedSymbol(node, semanticModel);
        }

        public static ISymbol GetDeclaredSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            return semanticModel.GetDeclaredSymbol(node);
        }

        public static ISymbol GetReferencedSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            return semanticModel.GetSymbolInfo(node).Symbol;
        }

        public static IEnumerable<ISymbol> GetCandidateReferencedSymbols(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            return semanticModel.GetSymbolInfo(node).CandidateSymbols;
        }

        public static bool NodeHasConstantValueNull(SyntaxNode node, SemanticModel model)
        {
            if (node == null || model == null)
            {
                return false;
            }
            Optional<object> value = model.GetConstantValue(node);
            return value.HasValue && value.Value == null;
        }

        public static bool NodeHasConstantValue<T>(SyntaxNode node, SemanticModel model, T expectedValue) where T : struct
        {
            if (node == null || model == null)
            {
                return false;
            }
            Optional<object> value = model.GetConstantValue(node);
            return value.HasValue &&
                   value.Value is T &&
                   ((T)value.Value).Equals(expectedValue);
        }

        public static ISymbol GetDeclaredOrReferencedSymbol(SyntaxNode node, SemanticModel model)
        {
            if (node == null)
            {
                return null;
            }

            return model.GetDeclaredSymbol(node) ?? model.GetSymbolInfo(node).Symbol;
        }
    }
}
