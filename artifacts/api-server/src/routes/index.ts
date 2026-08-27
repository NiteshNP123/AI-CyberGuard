import { Router, type IRouter } from "express";
import healthRouter from "./health";
import dashboardRouter from "./dashboard";
import analysisRouter from "./analysis";
import alertsRouter from "./alerts";
import incidentsRouter from "./incidents";
import networkRouter from "./network";
import dnsRouter from "./dns";
import authRouter from "./auth";
import wifiRouter from "./wifi";
import secretsRouter from "./secrets";
import settingsRouter from "./settings";

const router: IRouter = Router();

router.use(healthRouter);
router.use(dashboardRouter);
router.use(analysisRouter);
router.use(alertsRouter);
router.use(incidentsRouter);
router.use(networkRouter);
router.use(dnsRouter);
router.use(authRouter);
router.use(wifiRouter);
router.use(secretsRouter);
router.use(settingsRouter);

export default router;
