package sda.managers;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;
import sda.Sda;
import sda.SdaType;
import sda.ghidra.datatype.*;
import sda.ghidra.function.SFunction;
import sda.ghidra.function.SFunctionRange;
import sda.ghidra.function.SFunctionSignature;
import sda.ghidra.shared.STypeUnit;
import sda.util.DebugConsole;
import sda.util.ObjectHash;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class FunctionManager extends AbstractManager {
    public FunctionManager(Sda sda) {
        super(sda);
    }

    public long getFunctionOffset(Function function) {
        return getOffset(function.getEntryPoint());
    }

    public long getId(Function function) {
        return getFunctionOffset(function);
    }

    public Function findFunctionById(long id, boolean returnDefType) {
        Address addr = getAddress(id);
        Function function = getFunctionManager().getFunctionAt(addr);
        if(function == null && returnDefType) {
            return new UndefinedFunction(getProgram(), addr);
        }
        return function;
    }

    private List<AddressRange> getFunctionRanges(List<SFunctionRange> rangeDescs) {
        List<AddressRange> ranges = new ArrayList<>();
        for(SFunctionRange range : rangeDescs) {
            ranges.add(new AddressRangeImpl(
                    getAddress(range.getMinOffset()),
                    getAddress(range.getMaxOffset())
            ));
        }
        return ranges;
    }

    private Function changeOrCreate(SFunction funcDesc) {
        Function function = findFunctionById(funcDesc.getId(), false);

        AddressSet body = new AddressSet();
        for(AddressRange range : getFunctionRanges(funcDesc.getRanges())) {
            body.addRange(range.getMinAddress(), range.getMaxAddress());
        }

        if(function == null) {
            Address entryPoint = getAddress(funcDesc.getRanges().get(0).getMinOffset());
            try {
                function = getFunctionManager().createFunction(funcDesc.getName(), entryPoint, body, SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                e.printStackTrace();
            } catch (OverlappingFunctionException e) {
                e.printStackTrace();
            }
        } else {
            try {
                function.setName(funcDesc.getName(), SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
                e.printStackTrace();
            } catch (InvalidInputException e) {
                e.printStackTrace();
            }

            try {
                function.setBody(body);
            } catch (OverlappingFunctionException e) {
                e.printStackTrace();
            }
        }

        try {
            Parameter[] parameters = new Parameter[funcDesc.getSignature().getArgumentsSize()];
            for(int i = 0; i < parameters.length; i ++) {
                parameters[i] = new ParameterImpl(
                        funcDesc.getArgumentNames().get(i),
                        getSDA().getDataTypeManager().getType(funcDesc.getSignature().getArguments().get(i)),
                        getProgram()
                );
            }
            function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters);

            function.setReturnType(
                    getSDA().getDataTypeManager().getType(funcDesc.getSignature().getReturnType()),
                    SourceType.USER_DEFINED
            );
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        } catch (InvalidInputException e) {
            e.printStackTrace();
        }
        function.setComment(funcDesc.getComment());
        return function;
    }

    private boolean remove(SFunction funcDesc) {
        Function function = findFunctionById(funcDesc.getId(), false);
        if(function != null) {
            return getFunctionManager().removeFunction(function.getEntryPoint());
        }
        return false;
    }

    public void change_commit(List<SFunction> functions) {
        int id = getProgram().startTransaction("SDA: change functions");
        for(SFunction function : functions) {
            if(function.getName().equals("{remove}")) {
                remove(function);
                continue;
            }
            changeOrCreate(function);
        }
        getProgram().endTransaction(id, true);
    }

    private SFunction buildDesc(Function function) {
        SFunction funcDesc = new SFunction();
        funcDesc.setId(getId(function));
        funcDesc.setName(function.getName());
        funcDesc.setComment(function.getComment() != null ? function.getComment() : "");
        funcDesc.setArgumentNames(new ArrayList<>());

        SFunctionSignature signature = new SFunctionSignature();
        signature.setReturnType(new SdaType(function.getReturnType()).getUnitType());
        signature.setArguments(new ArrayList<>());
        for(Parameter parameter : function.getParameters()) {
            signature.addToArguments(new SdaType(parameter.getDataType()).getUnitType());
            funcDesc.addToArgumentNames(parameter.getName());
        }
        funcDesc.setSignature(signature);

        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            SFunctionRange rangeDesc = new SFunctionRange();
            rangeDesc.setMinOffset((int)getOffset(range.getMinAddress()));
            rangeDesc.setMaxOffset((int)getOffset(range.getMaxAddress()));
            funcDesc.addToRanges(rangeDesc);
        }

        return funcDesc;
    }

    private ObjectHash getHash(SFunction funcDesc) {
        ObjectHash hash = new ObjectHash();
        hash.addValue(funcDesc.getName());
        hash.addValue(funcDesc.getComment());

        List<STypeUnit> parameters = funcDesc.getSignature().getArguments();
        for (int i = 0; i < parameters.size(); i ++) {
            ObjectHash argHash = new ObjectHash();
            argHash.addValue(funcDesc.getArgumentNames().get(i));
            argHash.addValue(parameters.get(i).getTypeId());
            argHash.addValue(parameters.get(i).getPointerLvl());
            argHash.addValue(parameters.get(i).getArraySize());
            hash.join(argHash);
        }

        for(SFunctionRange range : funcDesc.getRanges()) {
            ObjectHash rangeHash = new ObjectHash();
            rangeHash.addValue(range.getMinOffset());
            rangeHash.addValue(range.getMaxOffset());
            hash.join(rangeHash);
        }

        return hash;
    }

    public List<SFunction> getAllFunctions(Map<Long, Long> hashmap) {
        List<SFunction> result = new ArrayList<>();
        Iterator<Function> functions = getFunctionManager().getFunctions(true);
        int i = 1500;
        while(functions.hasNext()) {
            if(i-- == 0) break;
            Function function = functions.next();
            if(true) {
                Long hash = hashmap.get(getId(function));
                SFunction desc = buildDesc(function);
                if (hash == null || hash.longValue() != getHash(desc).getHash()) {
                    result.add(desc);
                }
            }
        }
        return result;
    }

    private ghidra.program.model.listing.FunctionManager getFunctionManager() {
        return getProgram().getFunctionManager();
    }
}
