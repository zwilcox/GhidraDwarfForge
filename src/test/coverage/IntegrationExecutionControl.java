import java.io.File;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.SessionInfo;
import org.jacoco.core.tools.ExecFileLoader;

/** Produces invalid *real JaCoCo* input for the integration report's negative controls. */
public final class IntegrationExecutionControl {
    public static void main(String[] args) throws Exception {
        var loader = new ExecFileLoader();
        loader.load(new File(args[0]));
        switch (args[2]) {
            case "wrong-class" -> {
                var data = loader.getExecutionDataStore().getContents().iterator().next();
                loader.getExecutionDataStore().put(new ExecutionData(data.getId() ^ 1,
                    data.getName(), data.getProbes().clone()));
            }
            case "foreign" -> loader.getExecutionDataStore().put(
                new ExecutionData(42, "foreign/Injected", new boolean[] {true}));
            case "extra-session" -> loader.getSessionInfoStore().visitSessionInfo(new SessionInfo("extra", 1, 2));
            case "no-hits" -> loader.getExecutionDataStore().reset();
            default -> throw new IllegalArgumentException("unknown control");
        }
        loader.save(new File(args[1]), false);
    }
}
