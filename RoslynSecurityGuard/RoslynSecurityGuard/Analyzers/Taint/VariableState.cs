using static RoslynSecurityGuard.Analyzers.Taint.VariableTaint;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    /// <summary>
    /// Define the state of variable regarding can it be trust, where does it come from.
    /// 
    /// <code>struct</code> was chosen because the execution of the taint analysis will visited a lot.
    /// This may allow less heap allocation and less garbage collection.
    /// 
    /// <a href="https://msdn.microsoft.com/en-us/library/ms229017.aspx">Choosing Between Class and Struct</a>
    /// </summary>
    public struct VariableState
    {
        public VariableTaint taint { get; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="taint">Initial state</param>
        public VariableState(VariableTaint taint = UNKNOWN) {
            this.taint = taint;
        }

        /// <summary>
        /// Merge two different states. State are merge if a data structure accept new input or 
        /// if values are concatenate.
        /// </summary>
        /// <param name="secondState"></param>
        /// <returns></returns>
        public VariableState merge(VariableState secondState) {
            var newTaint = taint;

            switch (secondState.taint) {
                case (TAINTED):
                    newTaint = TAINTED;
                    break;
                case (UNKNOWN):
                    if(taint != TAINTED) newTaint = UNKNOWN;
                    break;
                case (SAFE):
                    if(taint != TAINTED && taint != UNKNOWN) newTaint = SAFE;
                    break;
                case (CONSTANT):
                    if (taint == SAFE) newTaint = SAFE;
                    else if (taint == CONSTANT) newTaint = CONSTANT;
                    break;
            }
            //It might be better to create a new instance.
            return new VariableState(newTaint);
        }

        
        public override string ToString() {
            return taint.ToString();
        }
    }

}
