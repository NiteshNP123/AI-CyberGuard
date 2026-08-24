import { Router, type IRouter } from "express";
import healthRouter from "./health";
import dashboardRouter from "./dashboard";
import analysisRouter from "./analysis";
import alertsRouter from "./alerts";

const router: IRouter = Router();

router.use(healthRouter);
router.use(dashboardRouter);
router.use(analysisRouter);
router.use(alertsRouter);

export default router;
