# Output backends for sigmac
# Copyright 2018 SOC Prime

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class QRadarBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qradar saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qradar"
    active = True
    reEscape = re.compile('(")')
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "\'%s\'"
    keyExpression = "%s"
    nullExpression = "%s is null"
    notNullExpression = "not (%s is null)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    aql_database = "events"

    def cleanKey(self, key):
        if " " in key:
            key = "\"%s\"" % (key)
        return key

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        elif type(node) in (str, int):
            return self.generateValueNode(node, False)
        elif type(node) == list:
            return self.generateListNode(node)
        else:
            raise TypeError(
                f"Node type {str(type(node))} was not expected in Sigma parse tree"
            )


    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                return f"{self.cleanKey(key)} ilike {self.generateValueNode(value, True)}"
            elif type(value) in (str, int):
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value, True))
            else:
                return self.mapExpression % (self.cleanKey(key), self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError(
                f"Backend does not support map values of type {str(type(value))}"
            )

    def generateMapItemListNode(self, key, value):
        itemslist = []
        for item in value:
            if type(item) == str and "*" in item:
                item = item.replace("*", "%")
                itemslist.append(
                    f'{self.cleanKey(key)} ilike {self.generateValueNode(item, True)}'
                )

            else:
                itemslist.append(
                    f'{self.cleanKey(key)} = {self.generateValueNode(item, True)}'
                )

        return '('+" or ".join(itemslist)+')'

    def generateValueNode(self, node, keypresent):
        if keypresent == False:
            return "UTF8(payload) ilike \'{0}{1}{2}\'".format("%", self.cleanValue(str(node)), "%")
        else:
            return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def generateAggregation(self, agg):
        if agg is None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield is None:
            self.qradarPrefixAgg = f"SELECT {agg.aggfunc_notrans}({agg.aggfield}) as agg_val from {self.aql_database} where"

            self.qradarSuffixAgg = f" group by {agg.aggfield} having agg_val {agg.cond_op} {agg.condition}"

        else:
            self.qradarPrefixAgg = f" SELECT {agg.aggfunc_notrans}({agg.aggfield}) as agg_val from {self.aql_database} where "

            self.qradarSuffixAgg = f" group by {agg.groupfield} having agg_val {agg.cond_op} {agg.condition}"


        return self.qradarPrefixAgg, self.qradarSuffixAgg

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            return result

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        self.parsedlogsource = sigmaparser.get_logsource().index
        if any("flow" in i for i in self.parsedlogsource):
            aql_database = "flows"
        else:
            aql_database = "events"
        qradarPrefix = (
            f"SELECT UTF8(payload) as search_payload from {aql_database} where "
        )

        if parsed.parsedAgg:
            (qradarPrefix, qradarSuffixAgg) = self.generateAggregation(parsed.parsedAgg)
            result = qradarPrefix + result
            result += qradarSuffixAgg
        else:
            result = qradarPrefix + result
        return result
