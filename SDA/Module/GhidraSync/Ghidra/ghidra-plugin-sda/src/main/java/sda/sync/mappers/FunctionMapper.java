package sda.sync.mappers;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import sda.Sda;
import sda.ghidra.function.SFunction;
import sda.ghidra.function.SFunctionRange;
import sda.ghidra.function.SFunctionSignature;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.sync.IMapper;
import sda.sync.SyncContext;

import java.util.ArrayList;
import java.util.List;

public class FunctionMapper implements IMapper {
    private Sda sda;
    public FunctionManager functionManager;
    private DataTypeMapper dataTypeMapper;

    public FunctionMapper(Sda sda, FunctionManager functionManager, DataTypeMapper dataTypeMapper) {
        this.sda = sda;
        this.functionManager = functionManager;
        this.dataTypeMapper = dataTypeMapper;
    }

    @Override
    public void load(SDataFullSyncPacket dataPacket) {
        for (SFunction funcDesc : dataPacket.functions) {
            Function function = findFunctionByGhidraId(funcDesc.getId());
            if(function == null) {
                try {
                    Address entryPoint = sda.getAddressByOffset(funcDesc.getRanges().get(0).getMinOffset());
                    function = functionManager.createFunction(funcDesc.getName(), entryPoint, getBodyByAddressRanges(funcDesc.getRanges()), SourceType.USER_DEFINED);
                } catch (InvalidInputException e) {
                    e.printStackTrace();
                } catch (OverlappingFunctionException e) {
                    e.printStackTrace();
                }
            } else {
                changeFunctionByDescGenerally(function, funcDesc);
            }
            changeFunctionByDescDeeply(function, funcDesc);
        }
    }

    public void upsert(SyncContext ctx, Function function) {
        ctx.dataPacket.functions.add(buildDesc(function));
    }

    private void changeFunctionByDescGenerally(Function function, SFunction funcDesc) {
        AddressSet body = getBodyByAddressRanges(funcDesc.getRanges());
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

    private void changeFunctionByDescDeeply(Function function, SFunction funcDesc) {
        try {
            Parameter[] parameters = new Parameter[funcDesc.getSignature().getArgumentsSize()];
            for(int i = 0; i < parameters.length; i ++) {
                parameters[i] = new ParameterImpl(
                        funcDesc.getArgumentNames().get(i),
                        dataTypeMapper.getTypeByDesc(funcDesc.getSignature().getArguments().get(i)),
                        sda.getProgram()
                );
            }
            function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters);

            function.setReturnType(
                    dataTypeMapper.getTypeByDesc(funcDesc.getSignature().getReturnType()),
                    SourceType.USER_DEFINED
            );
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        } catch (InvalidInputException e) {
            e.printStackTrace();
        }
        function.setComment(funcDesc.getComment());
    }

    private long getGhidraId(Function function) {
        return sda.getOffsetByAddress(function.getEntryPoint());
    }

    private SFunction buildDesc(Function function) {
        SFunction funcDesc = new SFunction();
        funcDesc.setId(getGhidraId(function));
        funcDesc.setName(function.getName());
        funcDesc.setComment(function.getComment() != null ? function.getComment() : "");
        funcDesc.setArgumentNames(new ArrayList<>());

        SFunctionSignature signature = new SFunctionSignature();
        signature.setReturnType(dataTypeMapper.buildTypeUnitDesc(function.getReturnType()));
        signature.setArguments(new ArrayList<>());
        for(Parameter parameter : function.getParameters()) {
            signature.addToArguments(dataTypeMapper.buildTypeUnitDesc(parameter.getDataType()));
            funcDesc.addToArgumentNames(parameter.getName());
        }
        funcDesc.setSignature(signature);

        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            SFunctionRange rangeDesc = new SFunctionRange();
            rangeDesc.setMinOffset((int)sda.getOffsetByAddress(range.getMinAddress()));
            rangeDesc.setMaxOffset((int)sda.getOffsetByAddress(range.getMaxAddress()) + 1);
            funcDesc.addToRanges(rangeDesc);
        }

        return funcDesc;
    }

    private AddressSet getBodyByAddressRanges(List<SFunctionRange> rangeDescs) {
        AddressSet body = new AddressSet();
        for(SFunctionRange range : rangeDescs) {
            body.addRange(
                    sda.getAddressByOffset(range.getMinOffset()),
                    sda.getAddressByOffset(range.getMaxOffset() - 1)
            );
        }
        return body;
    }

    private Function findFunctionByGhidraId(long id) {
        Address addr = sda.getAddressByOffset(id);
        return functionManager.getFunctionAt(addr);
    }
}
