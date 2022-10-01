import json
import os
import re
from typing import Dict, Optional, Union
from json import JSONDecodeError

from crytic_compile.platform import solc_standard_json
from crytic_compile.crytic_compile import CryticCompile
from crytic_compile.compilation_unit import CompilationUnit
from crytic_compile.compiler.compiler import CompilerVersion
from crytic_compile.platform.etherscan import Etherscan, _convert_version, _handle_multiple_files, _handle_single_file
from crytic_compile.platform.exceptions import InvalidCompilation
from slither.slither import Slither

from peth.eth.scan import ScanAPI
from peth.core import config

class Uniscan(Etherscan):

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def compile(self, crytic_compile: "CryticCompile", **kwargs: str) -> None:
        """
        target: <network>:<address>
        """

        target = self._target
        export_dir = os.path.join(
            config.OUTPUT_PATH, kwargs.get("etherscan_export_dir", "compile-contracts")
        )

        source_code: str = ""
        result: Dict[str, Union[bool, str, int]] = {}
        contract_name: str = ""

        chain, addr = target.split(':')
        result = ScanAPI.get_or_create_by_chain(chain).get_contract_info(addr)

        if not result:
            raise InvalidCompilation("Contract has no public source code: " + target)

        prefix = '-' + chain
        # Assert to help mypy
        assert isinstance(result["SourceCode"], str)
        assert isinstance(result["ContractName"], str)
        
        source_code = result["SourceCode"]
        contract_name = result["ContractName"]

        if not os.path.exists(export_dir):
            os.makedirs(export_dir)

        # Assert to help mypy
        assert isinstance(result["CompilerVersion"], str)
        assert "vyper" not in result["CompilerVersion"], "Vyper not supported."

        compiler_version = re.findall(
            r"\d+\.\d+\.\d+", _convert_version(result["CompilerVersion"])
        )[0]

        optimization_used: bool = result["OptimizationUsed"] == "1"

        optimize_runs = None
        if optimization_used:
            optimize_runs = int(result["Runs"])

        working_dir: Optional[str] = None

        try:
            # etherscan might return an object with two curly braces, {{ content }}
            dict_source_code = json.loads(source_code[1:-1])
            filenames, working_dir = _handle_multiple_files(
                dict_source_code, addr, prefix, contract_name, export_dir
            )
        except JSONDecodeError:
            try:
                # or etherscan might return an object with single curly braces, { content }
                dict_source_code = json.loads(source_code)
                filenames, working_dir = _handle_multiple_files(
                    dict_source_code, addr, prefix, contract_name, export_dir
                )
            except JSONDecodeError:
                filenames = [
                    _handle_single_file(source_code, addr, prefix, contract_name, export_dir)
                ]

        compilation_unit = CompilationUnit(crytic_compile, contract_name)

        compilation_unit.compiler_version = CompilerVersion(
            compiler=kwargs.get("solc", "solc"),
            version=compiler_version,
            optimized=optimization_used,
            optimize_runs=optimize_runs,
        )
        compilation_unit.compiler_version.look_for_installed_version()

        solc_standard_json.standalone_compile(filenames, compilation_unit, working_dir=working_dir)

def slither_from_chain_addr(chain, addr):
    target = f"{chain}:{addr}"
    platform = Uniscan(target)
    compile = CryticCompile(platform)
    s = Slither(compile)
    return s