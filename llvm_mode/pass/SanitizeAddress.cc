#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
class SanitizeAddress : public FunctionPass {
public:
  static char ID;
  SanitizeAddress() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    // errs() << "SanitizeAddress: ";
    // errs().write_escaped(F.getName()) << '\n';
    // AttributeList att_list = F.getAttributes();
    // AttributeList::iterator it;
    // LLVMContext& C = F.getContext();
    F.addFnAttr(Attribute::SanitizeAddress);
    // if (F.hasFnAttribute(Attribute::SanitizeAddress)) {
    //   errs() << "I have it!\n";
    // }
    // else {
    //   errs() << "I don't??\n";
    // }
    // AttributeList new_list = att_list.addAttribute(C, 0, Attribute::SanitizeAddress);
    // errs() << att_list.getAsString(1) << "\n";
    // try to print Attribute List:
    // for (auto const& i : att_list) {
      // AttributeSet new_set = i.addAttribute(C, Attribute::SanitizeAddress);
      // errs() << i.getAsString() << "\n";
      // errs() << new_set.getAsString() << "\n";
    // }
    // errs() << att_list.getNumAttrSets() << "\n";
    // F.addAttribute(0, "sanitize_address");
    return true;
  }
}; // end of struct Hello
}  // end of anonymous namespace

static void registerSanitizeAddressPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new SanitizeAddress());                                  
}

char SanitizeAddress::ID = 0;
static RegisterPass<SanitizeAddress> X("sanitizeaddress", 
                            "SanitizeAddress Pass");

static RegisterStandardPasses 
    RegisterParmesanLLVMPass(PassManagerBuilder::EP_CGSCCOptimizerLate,
                              registerSanitizeAddressPass);