using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using static SecurityCodeScan.Analyzers.Taint.VariableTaint;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// </summary>
    public class VariableState
    {
        public VariableTaint Taint { get; private set; }

        /// <summary>
        /// Contains Value only if Taint is constant. Otherwise returns null
        /// </summary>
        public object Value { get; private set; }

        public SyntaxNode Node { get; private set; }

        public  IReadOnlyDictionary<string, VariableState> PropertyStates => Properties;
        private Dictionary<string, VariableState>          Properties { get; set; }

        public VariableState(SyntaxNode node, VariableTaint taint = Unknown, object value = null)
        {
            Taint = taint;
            Value = null;
            if (Taint == Constant)
                Value = value;
            Node = node;
            Properties = new Dictionary<string, VariableState>();
        }

        public void ApplySanitizer(ulong newTaint)
        {
            if ((newTaint & (ulong)Unknown) != 0)
                throw new ArgumentOutOfRangeException();

            if (newTaint == (ulong)Tainted)
            {
                // special case for function taint sources
                Taint = Tainted;
                return;
            }

            if (Taint == Constant)
                return;

            Taint |= (VariableTaint)newTaint;
        }

        public void MergeTaint(VariableTaint newTaint)
        {
            if (newTaint == Unset)
                return;

            if (((Taint & Constant) != 0ul) && ((Taint & Safe) != 0ul))
                throw new ArgumentOutOfRangeException(); // precondition

            if (((newTaint & Constant) != 0ul) && ((newTaint & Safe) != 0ul))
                throw new ArgumentOutOfRangeException();

            if (Taint == Unset)
            {
                Taint = newTaint;
            }
            else if (Taint != Safe && newTaint != Safe &&
                     (Taint & (Unknown | Tainted)) != 0ul && ((Taint & Safe) != 0ul) &&
                     (newTaint & (Unknown | Tainted)) != 0ul && ((newTaint & Safe) != 0ul))
            {
                if (((Taint & Tainted) != 0ul) || ((newTaint & Tainted) != 0ul))
                    Taint = Tainted | (Taint & newTaint & Safe);
                else
                    Taint = Unknown | (Taint & newTaint & Safe);
            }
            else if ((Taint    == Constant && ((newTaint & Tainted) != 0ul) ||
                     (newTaint == Constant && ((Taint & Tainted) != 0ul))))
            {
                Taint = Tainted | ((Taint | newTaint) & Safe);
            }
            else if ((Taint == Constant && ((newTaint & Unknown) != 0ul) ||
                      (newTaint                                  == Constant && ((Taint & Unknown) != 0ul))))
            {
                Taint = Unknown | ((Taint | newTaint) & Safe);
            }
            else if ((Taint == Safe && ((newTaint & (Unknown | Tainted)) != 0ul)))
            {
                Taint = newTaint;
            }
            else if ((newTaint == Safe && ((Taint & (Unknown | Tainted)) != 0ul)))
            {
                //Taint = Taint;
            }
            else if(((newTaint & Tainted) != 0ul) || ((Taint & Tainted) != 0ul))
            {
                Taint = Tainted;
            }
            else if (((newTaint & Unknown) != 0ul) || ((Taint & Unknown) != 0ul))
            {
                Taint = Unknown;
            }
            else if (Taint == Constant && newTaint == Constant)
            {
                Taint = Constant;
            }
            else
            {
                Taint = Safe;
            }
        }

        /// <summary>
        /// Merge two different states. Use it to merge two states when value is overridden.
        /// </summary>
        public void Replace(VariableState secondState)
        {
            if (secondState.Taint == Unset)
                return;

            Taint = secondState.Taint;
            Value = Taint == Constant ? secondState.Value : null;
            Node  = secondState.Node;

            Properties = secondState.Properties;
        }

        public void AddOrMergeProperty(string identifier, VariableState secondState)
        {
            if (ReferenceEquals(this, secondState))
                throw new Exception("Recursive call detected.");

            if (PropertyStates.ContainsKey(identifier))
            {
                PropertyStates[identifier].Replace(secondState);
                MergeTaint(secondState.Taint);
            }
            else
            {
                Properties.Add(identifier, secondState);
            }
        }

#if DEBUG
        public override string ToString()
        {
            var sanitizerBits = Taint & Safe;
            if (sanitizerBits != 0ul && sanitizerBits != Safe)
                return $"{(Taint & ~Safe).ToString()} | {((ulong)sanitizerBits).ToString()}";

            return Taint.ToString();
        }
#endif
    }
}
