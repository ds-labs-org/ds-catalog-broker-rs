/*
 * Seeds this runtime's TargetNodeDirectory with the two new "harvest"
 * participant instances (see ../../run-harvest-bench.sh and
 * ../../../crawler-edc-fixture/run-instance.sh, reused unchanged for
 * those two participants). Mirrors the pattern eclipse-edc-connector's own
 * federated-catalog end-to-end test uses
 * (system-tests/e2e-federatedcatalog-tests/end2end-test/e2e-junit-runner/.../FederatedCatalogTest.java's
 * private SeedNodeExtension, read before writing this): @Inject
 * TargetNodeDirectory, insert() in prepare().
 *
 * A TargetNode's url is the participant's *base* DSP protocol endpoint
 * including the version segment (e.g. "http://127.0.0.1:19221/api/dsp/2025-1")
 * - NOT the full ".../catalog/request" path used by crates/crawler's own
 * participant config (compliance/harvest-bench/participants.ttl). Confirmed by reading FederatedCatalogTest's own node
 * construction (CONNECTOR_PROTOCOL.path() + "/" + V_2025_1_VERSION, no
 * "/catalog/request" suffix) - DspCatalogRequestAction/ProtocolRemoteMessageDispatcher
 * resolve the message-type-specific path suffix themselves from this base.
 *
 * Parameterized entirely via the HARVEST_TARGET_NODES env var so this
 * class needs no changes to point at different ports/ids - format:
 * semicolon-separated "id=name=url" triples, e.g.
 * "harvest-d=Harvest D=http://127.0.0.1:19221/api/dsp/2025-1;harvest-e=Harvest E=http://127.0.0.1:19321/api/dsp/2025-1"
 */
package harvest;

import org.eclipse.edc.crawler.spi.TargetNode;
import org.eclipse.edc.crawler.spi.TargetNodeDirectory;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

import java.util.ArrayList;
import java.util.List;

import static org.eclipse.edc.protocol.dsp.spi.type.Dsp2025Constants.DATASPACE_PROTOCOL_HTTP_V_2025_1;

@Extension(HarvestSeedExtension.NAME)
public class HarvestSeedExtension implements ServiceExtension {

    public static final String NAME = "federated-catalog-rs harvest-bench: TargetNode seed";

    @Inject
    private TargetNodeDirectory targetNodeDirectory;

    private ServiceExtensionContext context;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        this.context = context;
    }

    @Override
    public void prepare() {
        var monitor = context.getMonitor();
        var nodes = parseTargetNodes();
        for (var node : nodes) {
            targetNodeDirectory.insert(node);
            monitor.info(NAME + ": seeded TargetNode id='" + node.id() + "' url='" + node.targetUrl() + "'");
        }
        monitor.info(NAME + ": seeded " + nodes.size() + " target node(s) total");
    }

    private static List<TargetNode> parseTargetNodes() {
        var raw = System.getenv("HARVEST_TARGET_NODES");
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException(
                    "HARVEST_TARGET_NODES is not set - expected semicolon-separated \"id=name=url\" triples");
        }
        var nodes = new ArrayList<TargetNode>();
        for (var entry : raw.split(";")) {
            var trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            var parts = trimmed.split("=", 3);
            if (parts.length != 3) {
                throw new IllegalStateException("malformed HARVEST_TARGET_NODES entry (expected id=name=url): '" + trimmed + "'");
            }
            nodes.add(new TargetNode(parts[1], parts[0], parts[2], List.of(DATASPACE_PROTOCOL_HTTP_V_2025_1)));
        }
        if (nodes.isEmpty()) {
            throw new IllegalStateException("HARVEST_TARGET_NODES was set but contained no non-empty entries: '" + raw + "'");
        }
        return nodes;
    }
}
